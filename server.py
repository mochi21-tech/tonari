"""Companion App Local Server - File bridge & CLI bridge to Claude Code.

セキュリティ既定値:
- 待受は 127.0.0.1（ローカルのみ）。スマホから繋ぐ場合は環境変数 COMPANION_HOST=0.0.0.0 を明示的に指定する。
- すべてのエンドポイント（/health を除く）で共有トークン認証を必須とする。
  トークンは環境変数 COMPANION_TOKEN で指定。未指定なら bridge/.token に自動生成し、起動時に表示する。
  アプリの「接続設定」にこのトークンを入力すること。
- CORS は既定で無効（Androidアプリ運用では不要）。必要なら COMPANION_CORS_ORIGINS にカンマ区切りで指定。

CLIモード:
- POST /cli で claude -p をサブプロセスとして起動し、job_id を返す。
- GET /cli/stream/<job_id> でポーリングして途中経過・最終結果を取得する。
- claude -p の --output-format stream-json --verbose で途中経過をリアルタイムに受け取る。
"""

import asyncio
import base64
import binascii
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

BRIDGE_DIR = Path(__file__).parent / "bridge"
BRIDGE_DIR.mkdir(exist_ok=True)

# 起動中のプロセスがどのコードかを /health と起動バナーで確認するためのバージョン。
# 挙動が変わる修正を入れたら必ず日付を更新すること。
# （過去に「ファイルは直っているが起動中のプロセスが古い」事故があり、
#   pydanticが未知フィールドを黙って捨てるため気付けなかった）
SERVER_VERSION = "2026-07-16"

HOST = os.environ.get("COMPANION_HOST", "127.0.0.1")
PORT = int(os.environ.get("COMPANION_PORT", "8000"))

# --- サイズ制限（DoS / OOM 対策） ---
MAX_BODY_BYTES = int(os.environ.get("COMPANION_MAX_BODY_BYTES", str(30 * 1024 * 1024)))  # 30MB
MAX_ATTACHMENTS = 5
MAX_DECODED_BYTES = 12 * 1024 * 1024  # 1ファイルあたりのデコード後上限 12MB
MAX_TOTAL_DECODED_BYTES = 40 * 1024 * 1024  # リクエスト全体のデコード後上限 40MB

# --- 応答待ち時間（クライアントの read timeout と整合させること） ---
RESPONSE_TIMEOUT_SECONDS = 180
POLL_INTERVAL_SECONDS = 0.5

# --- MIME 許可リスト（拡張子は固定マップから選ぶ。ユーザー入力を信用しない） ---
ALLOWED_MIME_EXT = {
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
    "application/pdf": "pdf",
    "text/plain": "txt",
    "text/markdown": "md",
    "text/csv": "csv",
    "text/html": "html",
    "application/json": "json",
}


def _load_or_create_token() -> str:
    env_token = os.environ.get("COMPANION_TOKEN")
    if env_token:
        return env_token
    token_file = BRIDGE_DIR / ".token"
    if token_file.exists():
        existing = token_file.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    token = secrets.token_urlsafe(24)
    token_file.write_text(token, encoding="utf-8")
    return token


TOKEN = _load_or_create_token()

app = FastAPI(title="Companion Local Server")

_cors_origins = [o.strip() for o in os.environ.get("COMPANION_CORS_ORIGINS", "").split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["POST", "GET"],
        allow_headers=["content-type", "x-companion-token"],
    )


class BodySizeLimitMiddleware:
    """実際に受信したバイト数で本文サイズを制限する ASGI ミドルウェア。

    Content-Length ヘッダだけを見る方式は、chunked 転送やヘッダ無しのクライアントを止められない。
    ここでは receive() をラップして実バイト数を数え、上限超過で 413 を返す。
    本文は上限まではメモリに溜めて 1 メッセージとして下流へ再供給する（LAN用途で上限30MBなら許容範囲）。
    """

    def __init__(self, app, max_body_size: int):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 速い経路: Content-Length が明らかに上限超なら本文を読む前に拒否する
        headers = dict(scope.get("headers") or [])
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_body_size:
                    await self._reject(scope, receive, send, 413, "Request body too large")
                    return
            except ValueError:
                await self._reject(scope, receive, send, 400, "Invalid Content-Length")
                return

        total = 0
        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_body_size:
                await self._reject(scope, receive, send, 413, "Request body too large")
                return
            body.extend(chunk)
            more_body = message.get("more_body", False)

        buffered = bytes(body)
        sent = False

        async def cached_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": buffered, "more_body": False}
            return await receive()

        await self.app(scope, cached_receive, send)

    async def _reject(self, scope, receive, send, status: int, message: str):
        response = JSONResponse(status_code=status, content={"error": message})
        await response(scope, receive, send)


app.add_middleware(BodySizeLimitMiddleware, max_body_size=MAX_BODY_BYTES)


def require_token(x_companion_token: str | None = Header(default=None)):
    """共有トークンを検証する依存。タイミング安全に比較する。"""
    if not x_companion_token or not secrets.compare_digest(x_companion_token, TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")


class Message(BaseModel):
    role: str
    content: str


class AttachmentItem(BaseModel):
    base64: str
    mime_type: str


class ChatRequest(BaseModel):
    messages: list[Message]
    system_prompt: str | None = None
    model: str | None = None
    sensor_context: str = ""
    session_letter: str = ""
    request_id: str | None = None  # クライアント生成。リトライ時の重複排除に使う
    image: str | None = None
    image_front: str | None = None
    image_rear: str | None = None
    screenshot: str | None = None
    attachments: list[AttachmentItem] = Field(default_factory=list)
    audio: str | None = None
    audio_format: str | None = None
    audio_duration: int | None = None


class ControlRequest(BaseModel):
    command: str  # "start_loop" | "stop_loop"
    interval: int = 270  # seconds (start_loop only)
    request_id: str | None = None


class ChatResponse(BaseModel):
    content: str
    error: str | None = None


# クライアント request_id -> (timestamp, payload dict) の重複排除キャッシュ（成功応答のみ）
_recent_responses: dict[str, tuple[float, dict]] = {}
_DEDUP_TTL = 300.0

# ブリッジ方式で送信済みのセッションレター内容。同じ内容は2回目以降スキップする
_bridge_session_letter_sent: str = ""


class _InflightEntry:
    """処理中の同一 client_request_id を1つの owner に集約するための共有状態。

    owner（最初のリクエスト）だけが request ファイルを書き、response ファイルの出現を待つ。
    後続の同一リクエスト（待機者）は同じ event を await し、owner の結果(payload)をそのまま受け取る。
    これにより「待機者が応答ファイルを見逃して180秒待つ」「finally で他の待機者の情報を消す」競合を防ぐ。
    """

    def __init__(self, request_id: str):
        self.request_id = request_id
        self.event = asyncio.Event()
        self.payload: dict | None = None  # 成功時のみ設定。失敗/タイムアウトは None のまま


# クライアント request_id -> 処理中エントリ
_inflight: dict[str, _InflightEntry] = {}


def _prune_dedup_cache(now: float) -> None:
    expired = [k for k, (ts, _) in _recent_responses.items() if now - ts > _DEDUP_TTL]
    for k in expired:
        _recent_responses.pop(k, None)


def _safe_bridge_path(name: str) -> Path:
    """BRIDGE_DIR 外に出ないことを検証したパスを返す。"""
    candidate = (BRIDGE_DIR / name).resolve()
    if candidate.parent != BRIDGE_DIR.resolve():
        raise HTTPException(status_code=400, detail="Invalid path")
    return candidate


def _decode_checked(b64: str, total_so_far: int) -> bytes:
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Invalid base64 payload")
    if len(raw) > MAX_DECODED_BYTES:
        raise HTTPException(status_code=413, detail="Attachment too large")
    if total_so_far + len(raw) > MAX_TOTAL_DECODED_BYTES:
        raise HTTPException(status_code=413, detail="Total payload too large")
    return raw


@app.get("/health")
async def health():
    latest_session = None
    if _persistent_sessions:
        latest_session = max(_persistent_sessions.items(), key=lambda x: x[1].last_activity)[0]
    return {"status": "ok", "version": SERVER_VERSION, "current_session": latest_session}


def _cleanup_request(request_id: str) -> None:
    (BRIDGE_DIR / f"request_{request_id}.json").unlink(missing_ok=True)
    for f in BRIDGE_DIR.glob(f"request_{request_id}_*"):
        f.unlink(missing_ok=True)


def _timeout_response() -> ChatResponse:
    return ChatResponse(
        content="", error=f"Timeout: Claude Code did not respond within {RESPONSE_TIMEOUT_SECONDS}s"
    )


@app.post("/chat", dependencies=[Depends(require_token)])
async def chat(req: ChatRequest):
    now = time.time()
    _prune_dedup_cache(now)

    client_rid = req.request_id or str(uuid.uuid4())

    # 同一 client request_id の応答が直近にあれば再利用（リトライ重複排除）
    cached = _recent_responses.get(client_rid)
    if cached is not None:
        return cached[1]

    # 同一 client request_id がすでに処理中なら、owner の結果を待つ（重複ファイルを作らない）。
    existing = _inflight.get(client_rid)
    if existing is not None:
        try:
            await asyncio.wait_for(existing.event.wait(), timeout=RESPONSE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            return _timeout_response()
        if existing.payload is not None:
            return existing.payload
        # owner が失敗/タイムアウトした場合
        return ChatResponse(content="", error="リクエストの処理に失敗しました")

    # ここから owner（最初のリクエスト）の処理
    request_id = str(uuid.uuid4())[:8]
    entry = _InflightEntry(request_id)
    _inflight[client_rid] = entry

    request_file = BRIDGE_DIR / f"request_{request_id}.json"
    response_file = BRIDGE_DIR / f"response_{request_id}.json"

    try:
        total_decoded = 0
        request_data = {
            "id": request_id,
            "client_request_id": client_rid,
            "messages": [{"role": m.role, "content": m.content} for m in req.messages],
            "timestamp": now,
        }
        if req.system_prompt:
            request_data["system_prompt"] = req.system_prompt
        if req.model:
            request_data["model"] = req.model
        if req.sensor_context:
            request_data["sensor_context"] = req.sensor_context
        global _bridge_session_letter_sent
        _include_bridge_letter = False
        if req.session_letter and req.session_letter != _bridge_session_letter_sent:
            request_data["session_letter"] = req.session_letter
            _include_bridge_letter = True
        if req.image:
            raw = _decode_checked(req.image, total_decoded)
            total_decoded += len(raw)
            img_path = _safe_bridge_path(f"request_{request_id}_image.jpg")
            img_path.write_bytes(raw)
            request_data["image"] = str(img_path)
        if req.attachments:
            if len(req.attachments) > MAX_ATTACHMENTS:
                raise HTTPException(status_code=413, detail="Too many attachments")
            att_paths = []
            for i, a in enumerate(req.attachments):
                ext = ALLOWED_MIME_EXT.get(a.mime_type.lower())
                if ext is None:
                    raise HTTPException(status_code=400, detail=f"Unsupported mime_type: {a.mime_type}")
                raw = _decode_checked(a.base64, total_decoded)
                total_decoded += len(raw)
                att_path = _safe_bridge_path(f"request_{request_id}_att{i}.{ext}")
                att_path.write_bytes(raw)
                att_paths.append({"path": str(att_path), "mime_type": a.mime_type})
            request_data["attachments"] = att_paths
        if req.image_front:
            raw = _decode_checked(req.image_front, total_decoded)
            total_decoded += len(raw)
            front_path = _safe_bridge_path(f"request_{request_id}_front.jpg")
            front_path.write_bytes(raw)
            request_data["image_front"] = str(front_path)
        if req.image_rear:
            raw = _decode_checked(req.image_rear, total_decoded)
            total_decoded += len(raw)
            rear_path = _safe_bridge_path(f"request_{request_id}_rear.jpg")
            rear_path.write_bytes(raw)
            request_data["image_rear"] = str(rear_path)
        if req.screenshot:
            raw = _decode_checked(req.screenshot, total_decoded)
            total_decoded += len(raw)
            shot_path = _safe_bridge_path(f"request_{request_id}_screenshot.jpg")
            shot_path.write_bytes(raw)
            request_data["screenshot"] = str(shot_path)
        if req.audio:
            raw = _decode_checked(req.audio, total_decoded)
            total_decoded += len(raw)
            audio_path = _safe_bridge_path(f"request_{request_id}_audio.wav")
            audio_path.write_bytes(raw)
            request_data["audio"] = str(audio_path)
            request_data["audio_format"] = req.audio_format
            request_data["audio_duration"] = req.audio_duration
        request_file.write_text(
            json.dumps(request_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        # response_{id}.json の出現を待つ（owner のみがこのファイルを読み取り・削除する）
        deadline = time.time() + RESPONSE_TIMEOUT_SECONDS
        while time.time() < deadline:
            if response_file.exists():
                response_data = json.loads(response_file.read_text(encoding="utf-8"))
                response_file.unlink(missing_ok=True)
                _cleanup_request(request_id)
                # content に加え、express / tools をそのままアプリへ転送する
                payload: dict = {"content": response_data.get("content", "")}
                if response_data.get("touch_color") is not None:
                    payload["touch_color"] = response_data["touch_color"]
                if response_data.get("animation") is not None:
                    payload["animation"] = response_data["animation"]
                if response_data.get("tools") is not None:
                    payload["tools"] = response_data["tools"]
                if _include_bridge_letter:
                    _bridge_session_letter_sent = req.session_letter
                _recent_responses[client_rid] = (time.time(), payload)
                entry.payload = payload  # 待機者に同じ結果を返す
                return payload
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

        _cleanup_request(request_id)
        return _timeout_response()

    except HTTPException:
        _cleanup_request(request_id)
        raise
    except Exception as e:
        _cleanup_request(request_id)
        return ChatResponse(content="", error=str(e))
    finally:
        # 成功時は entry.payload が設定済み、失敗/タイムアウト時は None のまま待機者を起こす
        entry.event.set()
        _inflight.pop(client_rid, None)


@app.post("/control", dependencies=[Depends(require_token)])
async def control(req: ControlRequest):
    """アプリからClaude Codeセッションへ制御メッセージを送る。"""
    control_id = str(uuid.uuid4())[:8]
    control_file = BRIDGE_DIR / f"control_{control_id}.json"
    ack_file = BRIDGE_DIR / f"ack_{control_id}.json"

    control_data = {
        "id": control_id,
        "command": req.command,
        "interval": req.interval,
        "timestamp": time.time(),
    }
    control_file.write_text(
        json.dumps(control_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    deadline = time.time() + 30
    while time.time() < deadline:
        if ack_file.exists():
            ack_data = json.loads(ack_file.read_text(encoding="utf-8"))
            ack_file.unlink(missing_ok=True)
            control_file.unlink(missing_ok=True)
            return ack_data
        await asyncio.sleep(POLL_INTERVAL_SECONDS)

    control_file.unlink(missing_ok=True)
    return {"status": "timeout", "message": "Claude Code did not acknowledge within 30s"}


@app.get("/pending", dependencies=[Depends(require_token)])
async def pending():
    """Claude Code側から未処理リクエスト一覧を取得するエンドポイント。

    書き込み途中・破損した request ファイルが1件あっても全体を 500 にせず、
    その1件だけスキップする（運用中に一覧取得が止まらないように）。
    """
    requests = []
    skipped = []
    for f in sorted(BRIDGE_DIR.glob("request_*.json")):
        resp_file = BRIDGE_DIR / f.name.replace("request_", "response_")
        if resp_file.exists():
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError):
            # 壊れた1件は隔離対象として記録し、一覧からは除外する
            skipped.append(f.name)
            continue
        requests.append(data)
    result = {"pending": requests}
    if skipped:
        result["skipped"] = skipped
    return result


# =============================================================================
# CLI モード（stream-json 常駐プロセス）
#
# セッションごとに1つの claude -p プロセスを常駐させ、--input-format stream-json で
# 複数メッセージを同一プロセスに流す。--resume 不要で「Continue from where you left off.」
# が発生しない。途中の応答テキストも全て result に含める。
# =============================================================================

# 空文字列や誤ってクォート付きで設定された場合も既定値 "claude" に落とす
_ENV_CLAUDE_CMD = os.environ.get("COMPANION_CLAUDE_CMD", "").strip().strip('"').strip()
CLAUDE_CMD = _ENV_CLAUDE_CMD or "claude"
CLI_JOB_TTL = 600  # ジョブ情報の保持時間（秒）


def _resolve_claude_cmd() -> str | None:
    """claude の実行ファイルをインストール形態の差を吸収して解決する。解決できなければ None。

    - ネイティブ版 / WinGet / Homebrew / Linux: PATH 上に実体（claude.exe 等）がある → そのまま使える
    - npm / pnpm 版 (Windows): PATH にあるのは claude.cmd 等のシムだけ。
      CreateProcess は拡張子なしの "claude" に .exe しか補完しないため直接起動できず、
      シム(cmd.exe)経由だと引数の引用符が壊れる恐れもある → シムが指す実体 exe を探して直接使う。
    COMPANION_CLAUDE_CMD が指定されていれば無条件にそれを使う（利用者の明示指定が最優先）。
    毎回解決し直すので、サーバー起動後に claude を入れ直しても再起動不要で追従する。
    """
    if _ENV_CLAUDE_CMD:
        return CLAUDE_CMD
    found = shutil.which(CLAUDE_CMD)
    if not found:
        return None
    found_path = Path(found)
    if found_path.suffix.lower() not in (".cmd", ".bat", ".ps1"):
        return found
    # npm 標準レイアウトの実体 exe
    npm_exe = found_path.parent / "node_modules" / "@anthropic-ai" / "claude-code" / "bin" / "claude.exe"
    if npm_exe.exists():
        return str(npm_exe)
    # レイアウトが違うシム(pnpm等)は、シム本文に書かれた claude.exe への相対パスを拾う
    try:
        shim_text = found_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        shim_text = ""
    m = re.search(r"%(?:dp0|~dp0)%?\\?([^\"\r\n%]*claude\.exe)", shim_text, re.IGNORECASE)
    if m:
        candidate = found_path.parent / m.group(1).strip().lstrip("\\")
        if candidate.exists():
            return str(candidate)
    if found_path.suffix.lower() == ".ps1":
        # .ps1 は CreateProcess で実行できない（WinError 193）。兄弟の実体/シムを探し、無ければ解決失敗
        for sibling in ("claude.exe", "claude.cmd", "claude.bat"):
            cand = found_path.with_name(sibling)
            if cand.exists():
                return str(cand)
        return None
    # 実体が見つからなければ .cmd/.bat シムをそのまま返す（CreateProcess は cmd.exe 経由で起動できる。
    # cmd.exe 経由でも安全なように、claude の argv に入るクライアント入力は /cli 側で形式検証している）
    return found
MCP_TOOLS_PATH = Path(__file__).parent / "mcp_tools.py"
SESSION_IDLE_TIMEOUT = 0  # 0 = アイドルタイムアウト無効（サーバー起動中はずっと常駐）


class CliRequest(BaseModel):
    message: str
    session_id: str  # アプリ側で生成・管理するUUID
    session_letter: str = ""
    pinned_memories: str = ""
    sensor_context: str = ""
    attachments: list[AttachmentItem] = Field(default_factory=list)
    image_front: str | None = None
    image_rear: str | None = None
    audio: str | None = None
    audio_format: str | None = None
    audio_duration: int | None = None
    screenshot: str | None = None
    model: str | None = None
    effort: str | None = None
    request_id: str | None = None
    health_data: str | None = None


# クライアント入力のうち claude の argv やファイル名に入るものは形式を固定する。
# session_id: パストラバーサル防止 + .cmd シム経由(cmd.exe)起動時のメタ文字注入防止
# model / effort: 同じく argv に入るため、使われ得る文字だけに絞る
# 角括弧は claude-opus-4-6[1m] のような1Mコンテキスト指定で使う（注入に使える文字ではない）
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9._:/\[\]-]{1,128}$")
_EFFORT_RE = re.compile(r"^[a-z]{1,16}$")

CLI_TEMP_DIR = BRIDGE_DIR / "cli_temp"
CLI_TEMP_DIR.mkdir(exist_ok=True)
HEALTH_DATA_PATH = BRIDGE_DIR / "health_data.json"
_SESSION_LETTER_SENT_DIR = BRIDGE_DIR / "letter_sent"
_SESSION_LETTER_SENT_DIR.mkdir(exist_ok=True)


class _CliJob:
    """1つのメッセージ（ターン）の状態を管理する。"""

    def __init__(self, job_id: str, session_id: str):
        self.job_id = job_id
        self.session_id = session_id
        self.events: list[dict] = []
        self.done = False
        self.result_text: str | None = None
        self.error: str | None = None
        self.created_at = time.time()
        self.temp_files: list[Path] = []
        self._event_index = 0
        self._assistant_texts: list[str] = []
        self._thinking_texts: list[str] = []
        self._pending_intermediates: list[str] = []
        self._last_intermediate_text_idx: int = -1
        self._included_context = False
        self._included_session_letter = False
        self.result_delivered = False

    def add_event(self, event: dict) -> None:
        event["index"] = self._event_index
        self.events.append(event)
        self._event_index += 1

    def cleanup_temp(self) -> None:
        for f in self.temp_files:
            f.unlink(missing_ok=True)


_cli_jobs: dict[str, _CliJob] = {}


def _prune_cli_jobs() -> None:
    now = time.time()
    expired = [k for k, j in _cli_jobs.items() if now - j.created_at > CLI_JOB_TTL and j.done]
    for k in expired:
        _cli_jobs.pop(k, None)


def _save_cli_temp(job: _CliJob, name: str, data: bytes) -> Path:
    """CLIジョブ用の一時ファイルを保存し、ジョブのcleanupリストに追加する。"""
    path = CLI_TEMP_DIR / f"{job.job_id}_{name}"
    path.write_bytes(data)
    job.temp_files.append(path)
    return path


def _build_cli_message(req: CliRequest, job: _CliJob, *, include_context: bool = True, include_session_letter: bool = True) -> str:
    """アプリからのリクエストを1つのメッセージ文字列に組み立てる。"""
    parts = []
    if req.sensor_context:
        parts.append(req.sensor_context)
    if include_context and req.pinned_memories:
        parts.append(f"[大切なこと]\n{req.pinned_memories}")
        # 終端マーカー。ログクリーナーがブロックごと除去するための目印(セッションレターと同方式)
        parts.append("[大切なことここまで]")
    if include_session_letter and req.session_letter:
        # 手紙の直後に単独行の区切り線を置く。ログクリーナー(extract_thinking/rebuild_log_chunks)が
        # 「手紙だけを切除して後続のユーザーメッセージを残す」ための目印(2026-07-05)
        parts.append(f"[前のセッションからの手紙]\n{req.session_letter}")
        # 終端マーカー(汎用記号---から誤爆しない専用の札)
        parts.append("[セッションレターここまで]")

    file_refs = []
    total_decoded = 0
    if req.attachments:
        for i, a in enumerate(req.attachments):
            ext = ALLOWED_MIME_EXT.get(a.mime_type.lower(), "bin")
            raw = _decode_checked(a.base64, total_decoded)
            total_decoded += len(raw)
            path = _save_cli_temp(job, f"att{i}.{ext}", raw)
            file_refs.append(f"[添付{i + 1}: {path}]")
    if req.image_front:
        raw = _decode_checked(req.image_front, total_decoded)
        total_decoded += len(raw)
        path = _save_cli_temp(job, "front.jpg", raw)
        file_refs.append(f"[フロントカメラ: {path}]")
    if req.image_rear:
        raw = _decode_checked(req.image_rear, total_decoded)
        total_decoded += len(raw)
        path = _save_cli_temp(job, "rear.jpg", raw)
        file_refs.append(f"[リアカメラ: {path}]")
    if req.screenshot:
        raw = _decode_checked(req.screenshot, total_decoded)
        total_decoded += len(raw)
        path = _save_cli_temp(job, "screenshot.jpg", raw)
        file_refs.append(f"[スクリーンショット: {path}]")
    if req.audio:
        raw = _decode_checked(req.audio, total_decoded)
        total_decoded += len(raw)
        path = _save_cli_temp(job, "audio.wav", raw)
        file_refs.append(f"[音声: {path}]")
    if file_refs:
        parts.append("\n".join(file_refs))

    parts.append(req.message)
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# 常駐プロセス管理
# ---------------------------------------------------------------------------

class _PersistentSession:
    """セッションごとに1つの常駐 claude -p プロセスを管理する。"""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.process: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task | None = None
        self._current_job: _CliJob | None = None
        self._model: str | None = None
        self._effort: str | None = None
        self.last_activity = time.time()
        self._context_sent = False
        self._session_letter_sent = self._letter_sent_marker.exists()
        self._last_completed_job: _CliJob | None = None
        self._last_jsonl_mtime: float = 0.0
        # /sync がアプリ発のプロンプト（HB・センサー付きメッセージ等）を
        # 「PC側で打った言葉」と誤ってアプリに返さないための送信済みリスト
        self._sent_user_texts: list[str] = []

    @property
    def _letter_sent_marker(self) -> Path:
        return _SESSION_LETTER_SENT_DIR / f"{self.session_id}.sent"

    def _persist_letter_sent(self) -> None:
        """セッションレター送信済みをファイルに永続化する（プロセス再起動対策）。"""
        try:
            self._letter_sent_marker.write_text("1", encoding="utf-8")
        except OSError:
            pass

    def _snapshot_jsonl_mtime(self) -> None:
        """JONLファイルの更新時刻を記録する。"""
        jsonl_path = _find_session_jsonl(self.session_id)
        if jsonl_path is not None:
            try:
                self._last_jsonl_mtime = jsonl_path.stat().st_mtime
            except OSError:
                pass

    async def ensure_started(self, model: str | None, effort: str | None) -> None:
        """プロセスが動いていなければ起動。model/effort 変更時は再起動。
        他プロセス（PC Claude Code等）がJONLに書き込んでいた場合も再起動する。"""
        needs_restart = (
            self.process is None
            or self.process.returncode is not None
            or self._model != model
            or self._effort != effort
        )
        if not needs_restart:
            jsonl_path = _find_session_jsonl(self.session_id)
            if jsonl_path is not None:
                try:
                    current_mtime = jsonl_path.stat().st_mtime
                    if current_mtime > self._last_jsonl_mtime:
                        needs_restart = True
                        print(f"SESSION RESTART [{self.session_id[:8]}]: JSONL modified externally", flush=True)
                except OSError:
                    pass
        if not needs_restart:
            return

        await self._stop()

        session_exists = _find_session_jsonl(self.session_id) is not None
        claude_cmd = _resolve_claude_cmd()
        if not claude_cmd:
            raise Exception(
                "claude 実行ファイルが見つかりません。Claude Code をインストールするか、"
                "環境変数 COMPANION_CLAUDE_CMD でフルパスを指定してください"
            )
        cmd = [claude_cmd, "-p",
               "--input-format", "stream-json",
               "--output-format", "stream-json",
               "--verbose",
               ]
        if session_exists:
            cmd.extend(["--resume", self.session_id])
        else:
            cmd.extend(["--session-id", self.session_id])
        if MCP_TOOLS_PATH.exists():
            # インラインJSONは .cmd シム(cmd.exe)経由で起動した場合に引用符が壊れるため、
            # ファイルに書き出してパスで渡す（--mcp-config はファイルパスも受け付ける）
            mcp_config_file = BRIDGE_DIR / "mcp_config.json"
            mcp_config_content = json.dumps({"mcpServers": {"companion": {
                "type": "stdio",
                # PATH の "python" に依存しない（配布先に python が無い / Store スタブの環境対策）
                "command": sys.executable,
                "args": [str(MCP_TOOLS_PATH.resolve())],
                "env": {"COMPANION_BRIDGE_DIR": str(BRIDGE_DIR.resolve())},
            }}}, ensure_ascii=False, indent=2)
            # 起動中の別セッションの claude が読んでいる最中に truncate しないよう、
            # 内容が変わる時だけ書き直す（内容は環境が同じなら毎回同一）
            try:
                unchanged = mcp_config_file.read_text(encoding="utf-8") == mcp_config_content
            except OSError:
                unchanged = False
            if not unchanged:
                mcp_config_file.write_text(mcp_config_content, encoding="utf-8")
            cmd.extend(["--mcp-config", str(mcp_config_file)])
        if model:
            cmd.extend(["--model", model])
        if effort:
            cmd.extend(["--effort", effort])

        self._model = model
        self._effort = effort
        self._context_sent = session_exists
        self._session_letter_sent = session_exists or self._letter_sent_marker.exists()

        mode = "resume" if session_exists else "new"
        print(f"SESSION START [{self.session_id[:8]}]: mode={mode}, model={model}, effort={effort}", flush=True)

        self.process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=10 * 1024 * 1024,  # 10MB — thinkingブロック等の巨大イベント対策
        )
        self._reader_task = asyncio.create_task(self._read_loop())
        self._snapshot_jsonl_mtime()

    async def send_message(self, message: str, job: _CliJob) -> None:
        """メッセージを常駐プロセスの stdin に書き込む。"""
        if self.process is None or self.process.stdin is None or self.process.returncode is not None:
            raise Exception("プロセスが起動していません")
        if self._current_job and not self._current_job.done:
            raise Exception("前のメッセージがまだ処理中です")

        self._current_job = job
        self.last_activity = time.time()
        self._sent_user_texts.append(message)
        if len(self._sent_user_texts) > 50:
            del self._sent_user_texts[:-50]

        msg = json.dumps(
            {"type": "user", "message": {"role": "user", "content": message}},
            ensure_ascii=False,
        ) + "\n"
        self.process.stdin.write(msg.encode("utf-8"))
        await self.process.stdin.drain()

    async def _read_loop(self) -> None:
        """stdout を継続的に読み、イベントを現在のジョブに振り分ける。"""
        proc = self.process
        if proc is None or proc.stdout is None:
            return

        async def _drain_stderr():
            if proc.stderr is None:
                return
            while True:
                chunk = await proc.stderr.read(4096)
                if not chunk:
                    break

        asyncio.create_task(_drain_stderr())
        event_count = 0

        while True:
            try:
                line = await proc.stdout.readline()
            except Exception as e:
                print(f"READ_LOOP [{self.session_id[:8]}]: readline exception: {e}", flush=True)
                break
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                event = json.loads(text)
            except json.JSONDecodeError:
                continue

            etype = event.get("type", "?")
            esubtype = event.get("subtype", "")
            event_count += 1

            job = self._current_job
            if job is None or job.done:
                continue

            job.add_event(event)

            if etype == "assistant":
                msg = event.get("message", {})
                content = msg.get("content", [])
                if isinstance(content, list):
                    has_tool_use = any(b.get("type") == "tool_use" for b in content if isinstance(b, dict))
                    if has_tool_use and job._assistant_texts:
                        current_idx = len(job._assistant_texts) - 1
                        if current_idx > job._last_intermediate_text_idx:
                            job._pending_intermediates.append(job._assistant_texts[-1])
                            job._last_intermediate_text_idx = current_idx
                    for block in content:
                        if isinstance(block, dict):
                            if block.get("type") == "text":
                                t = block.get("text", "")
                                if t and "previous response had no visible output" not in t:
                                    job._assistant_texts.append(t)
                            elif block.get("type") == "thinking":
                                t = block.get("thinking", "")
                                if t:
                                    job._thinking_texts.append(t)

            if etype == "result":
                if job._assistant_texts:
                    job.result_text = "\n\n".join(job._assistant_texts)
                else:
                    raw_result = event.get("result", "")
                    if "previous response had no visible output" in raw_result:
                        raw_result = raw_result.replace("[Your previous response had no visible output. Please continue and produce a user-visible response.]", "").strip()
                    job.result_text = raw_result
                if not job.session_id and event.get("session_id"):
                    job.session_id = event["session_id"]
                if job._included_context:
                    self._context_sent = True
                if job._included_session_letter:
                    self._session_letter_sent = True
                    self._persist_letter_sent()
                job.done = True
                job.cleanup_temp()
                self._last_completed_job = job
                self.last_activity = time.time()
                self._snapshot_jsonl_mtime()
                print(f"CLI DONE [{job.job_id}]: events={len(job.events)}, texts={len(job._assistant_texts)}", flush=True)

        if proc.returncode is None:
            try:
                await proc.wait()
            except Exception:
                pass

        if self._current_job and not self._current_job.done:
            job = self._current_job
            job.error = f"claude -p process exited unexpectedly (code {proc.returncode})"
            job.done = True
            job.cleanup_temp()
            print(f"CLI ERROR [{job.job_id}]: process exited with code {proc.returncode}", flush=True)

    async def _stop(self) -> None:
        if self.process is not None and self.process.returncode is None:
            try:
                if self.process.stdin:
                    self.process.stdin.close()
                self.process.kill()
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except Exception:
                pass
        self.process = None
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
            self._reader_task = None


_persistent_sessions: dict[str, _PersistentSession] = {}


async def _prune_idle_sessions() -> None:
    """アイドル状態の常駐プロセスを終了する。SESSION_IDLE_TIMEOUT=0 なら何もしない。"""
    if SESSION_IDLE_TIMEOUT <= 0:
        return
    now = time.time()
    to_remove = [sid for sid, s in _persistent_sessions.items()
                 if now - s.last_activity > SESSION_IDLE_TIMEOUT]
    for sid in to_remove:
        s = _persistent_sessions.pop(sid)
        await s._stop()
        print(f"SESSION PRUNED [{sid[:8]}]: idle timeout", flush=True)


@app.post("/cli", dependencies=[Depends(require_token)])
async def cli_start(req: CliRequest):
    """常駐プロセスにメッセージを送り、job_id を返す。"""
    _prune_cli_jobs()
    await _prune_idle_sessions()

    if not _UUID_RE.fullmatch(req.session_id):
        raise HTTPException(status_code=400, detail="session_id はUUID形式で指定してください")
    if req.model and not _MODEL_RE.fullmatch(req.model):
        raise HTTPException(status_code=400, detail="model の形式が不正です")
    if req.effort and not _EFFORT_RE.fullmatch(req.effort):
        raise HTTPException(status_code=400, detail="effort の形式が不正です")

    claude_cmd = _resolve_claude_cmd()
    if not claude_cmd or not shutil.which(claude_cmd):
        raise HTTPException(
            status_code=500,
            detail=(
                f"'{claude_cmd or CLAUDE_CMD}' が見つかりません。Claude Codeがインストールされているか確認してください。"
                "見つからない場合は、環境変数 COMPANION_CLAUDE_CMD に claude 実行ファイルのフルパスを指定してください。"
            ),
        )

    job_id = str(uuid.uuid4())[:8]
    job = _CliJob(job_id, req.session_id)

    if req.health_data:
        try:
            HEALTH_DATA_PATH.write_text(req.health_data, encoding="utf-8")
        except Exception:
            pass

    if req.session_id not in _persistent_sessions:
        _persistent_sessions[req.session_id] = _PersistentSession(req.session_id)
    session = _persistent_sessions[req.session_id]

    prev = session._last_completed_job
    if prev is not None and not prev.result_delivered and prev.result_text is not None and not prev.error:
        print(f"CLI RECOVER [{prev.job_id}]: returning undelivered result for session {req.session_id[:8]}", flush=True)
        prev.result_delivered = True
        recovered_resp: dict = {"job_id": prev.job_id, "session_id": req.session_id, "recovered": True, "result": prev.result_text}
        if len(prev._assistant_texts) > 1:
            recovered_resp["result_parts"] = prev._assistant_texts
        if prev._thinking_texts:
            recovered_resp["thinking"] = prev._thinking_texts
        return recovered_resp

    try:
        await session.ensure_started(req.model, req.effort)
        include_context = not session._context_sent
        include_session_letter = not session._session_letter_sent
        message = _build_cli_message(req, job, include_context=include_context, include_session_letter=include_session_letter)
        if include_context:
            job._included_context = True
        if include_session_letter and req.session_letter:
            job._included_session_letter = True
        _cli_jobs[job_id] = job
        await session.send_message(message, job)
    except Exception as e:
        job.cleanup_temp()
        raise HTTPException(status_code=500, detail=f"メッセージの送信に失敗しました: {e}")

    print(f"CLI SEND [{job_id}]: session={req.session_id}, msg_len={len(message)}", flush=True)
    return {"job_id": job_id, "session_id": req.session_id}


@app.get("/cli/stream/{job_id}", dependencies=[Depends(require_token)])
async def cli_stream(job_id: str, after: int = -1):
    """ポーリング用。指定インデックス以降のイベントを返す。"""
    job = _cli_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    events = [e for e in job.events if e.get("index", 0) > after]

    response: dict = {"events": events, "done": job.done}
    if job._pending_intermediates:
        response["intermediate_messages"] = job._pending_intermediates
        job._pending_intermediates = []
    if job.done:
        response["session_id"] = job.session_id
        if job.result_text is not None:
            response["result"] = job.result_text
        if len(job._assistant_texts) > 1:
            response["result_parts"] = job._assistant_texts
        if job._thinking_texts:
            response["thinking"] = job._thinking_texts
        if job.error:
            response["error"] = job.error
        job.result_delivered = True
        job.events = []
    return response


# =============================================================================
# セッション同期（PC側のClaude Code対話をアプリに反映）
# =============================================================================

CLAUDE_PROJECTS_DIR = Path.home() / ".claude" / "projects"


def _find_session_jsonl(session_id: str) -> Path | None:
    """session_id に対応する JSONL ファイルを探す。複数プロジェクトを検索する。"""
    if not CLAUDE_PROJECTS_DIR.exists():
        return None
    for project_dir in CLAUDE_PROJECTS_DIR.iterdir():
        if not project_dir.is_dir():
            continue
        candidate = project_dir / f"{session_id}.jsonl"
        if candidate.exists():
            return candidate
    return None


def _extract_text(message: dict | str) -> str:
    """message フィールドからテキストを抽出する。"""
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        content = message.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            texts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
            return "\n".join(texts)
    return ""


def _extract_text_with_thinking(message: dict | str) -> str:
    """message フィールドからthinking + テキストを抽出する。"""
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        content = message.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            thinkings = [b.get("thinking", "") for b in content if isinstance(b, dict) and b.get("type") == "thinking"]
            texts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
            result = ""
            if thinkings:
                combined = "\n\n".join(t for t in thinkings if t)
                if combined:
                    result = f"<thinking>\n{combined}\n</thinking>\n"
            result += "\n".join(texts)
            return result
    return ""


def _is_app_origin_user_text(session_id: str, text: str) -> bool:
    """JSONL上のuserメッセージが「アプリ（サーバー）が組み立てたプロンプト」かを判定する。

    HBプロンプトやセンサー・添付付きメッセージはアプリ側のDBに元の形で存在する
    （またはそもそも表示すべきでない）ため、/sync で返すとチャット欄に
    生プロンプトが出てしまう（2026-07-16 S26検証で発覚）。
    """
    session = _persistent_sessions.get(session_id)
    if session is not None and text in session._sent_user_texts:
        return True
    # サーバー再起動後の保険: サーバーしか知り得ない痕跡で判定する
    if str(CLI_TEMP_DIR) in text:  # 添付・カメラ・スクショ・音声のファイル参照
        return True
    if "[大切なことここまで]" in text or "[セッションレターここまで]" in text:
        return True
    return False


@app.get("/sync/{session_id}", dependencies=[Depends(require_token)])
async def sync_session(session_id: str, after: str = ""):
    """PC側のClaude Codeセッションからuser/assistantメッセージを取得する。

    after: ISO 8601タイムスタンプ。これより後のメッセージのみ返す。
    """
    # session_id はパス組み立てに使うため、UUID形式以外は受け付けない（パストラバーサル防止）
    if not _UUID_RE.fullmatch(session_id):
        return {"messages": [], "error": "Invalid session_id"}
    # アプリ発のジョブが進行中の間は同期しない。進行中のターンを途中で返すと、
    # アプリが後で受け取るリアルタイム応答と二重に表示される（2026-07-16 S26検証で発覚）
    active = _persistent_sessions.get(session_id)
    if active is not None and active._current_job is not None and not active._current_job.done:
        return {"messages": [], "busy": True}
    jsonl_path = _find_session_jsonl(session_id)
    if jsonl_path is None:
        return {"messages": [], "error": "Session not found"}

    messages = []
    pending_thinking = ""
    try:
        with open(jsonl_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                entry_type = entry.get("type", "")
                if entry_type not in ("user", "assistant"):
                    continue
                ts = entry.get("timestamp", "")
                if after and ts <= after:
                    continue
                extractor = _extract_text_with_thinking if entry_type == "assistant" else _extract_text
                text = extractor(entry.get("message", ""))
                if not text:
                    continue
                if text.lstrip().startswith("<task-notification"):
                    continue
                if entry_type == "user" and _is_app_origin_user_text(session_id, text):
                    pending_thinking = ""
                    continue
                if entry_type == "assistant":
                    stripped = text.strip()
                    if stripped.startswith("<thinking>") and stripped.endswith("</thinking>"):
                        pending_thinking = text
                        continue
                    if pending_thinking:
                        text = pending_thinking + text
                        pending_thinking = ""
                if entry_type != "assistant":
                    pending_thinking = ""
                messages.append({
                    "role": entry_type,
                    "content": text,
                    "timestamp": ts,
                })
        if pending_thinking:
            messages.append({
                "role": "assistant",
                "content": pending_thinking,
                "timestamp": ts,
            })
    except OSError as e:
        return {"messages": [], "error": str(e)}

    return {"messages": messages}


@app.on_event("shutdown")
async def _shutdown_sessions():
    for s in list(_persistent_sessions.values()):
        await s._stop()
    _persistent_sessions.clear()


if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print(f"Companion Local Server (version {SERVER_VERSION}) listening on http://{HOST}:{PORT}")
    if HOST in ("127.0.0.1", "localhost"):
        print("※ ローカルのみ待受中。スマホから繋ぐには環境変数 COMPANION_HOST=0.0.0.0 を指定してください。")
    _claude_resolved = _resolve_claude_cmd()
    if _claude_resolved and shutil.which(_claude_resolved):
        print(f"claude CLI: {_claude_resolved}")
    else:
        print("claude CLI: 見つかりません。CLIモードは使えません。"
              "環境変数 COMPANION_CLAUDE_CMD で実行ファイルを指定できます。")
    print(f"認証トークン (アプリの接続設定に入力): {TOKEN}")
    print("=" * 60, flush=True)
    uvicorn.run(app, host=HOST, port=PORT)
