"""Companion App MCP Tools Server

Claude Code の MCP サーバーとして動作し、アプリ固有のツールを提供する。
stdio トランスポートで Claude Code と通信する。

副作用系ツール（remember等）はアプリ側で stream-json の
tool_use イベントをパースして実行する。このサーバーは成功を返すだけ。
データ返却系ツール（get_sleep_events）はファイルから読み取って返す。

server.py が --mcp-config でこのサーバーを自動登録するため、
ユーザーによる手動設定は不要。
"""

import asyncio
import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

BRIDGE_DIR = Path(os.environ.get("COMPANION_BRIDGE_DIR", ""))
HEALTH_DATA_PATH = BRIDGE_DIR / "health_data.json" if BRIDGE_DIR.name else None

# show_image: Mac側の画像を bridge/images/ にコピーし、アプリが GET /cli/image/{id} で取りに来る。
# id は「呼び出し時の path 文字列」の sha256 先頭32桁。アプリ側も同じ計算で id を出す（server.py側の注入不要）
IMAGES_DIR = BRIDGE_DIR / "images" if BRIDGE_DIR.name else None
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
IMAGE_MAX_BYTES = 12 * 1024 * 1024

# request_permission: Claude Code の --permission-prompt-tool から呼ばれる。
# bridge/permissions/{id}.request.json を書き、server.py 経由でアプリが {id}.response.json を書くまで待つ。
# 応答が来なければ deny（= 従来の -p モードの自動denyと同じ結果に落ちる）
PERMISSIONS_DIR = BRIDGE_DIR / "permissions" if BRIDGE_DIR.name else None
PERMISSION_TIMEOUT_SECONDS = float(os.environ.get("COMPANION_PERMISSION_TIMEOUT", "300"))
PERMISSION_POLL_SECONDS = 0.5


def image_id_for(path_str: str) -> str:
    return hashlib.sha256(path_str.encode("utf-8")).hexdigest()[:32]


server = Server("companion")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="remember",
            description="大切なことに新しい記憶を追加する。AIが常に知っている情報として保存される。",
            inputSchema={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "覚えておきたい内容",
                    },
                },
                "required": ["content"],
            },
        ),
        Tool(
            name="forget",
            description="大切なことから記憶を削除する。不要になった情報や古くなった情報を消す時に使う。",
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer",
                        "description": "削除する記憶のID",
                    },
                },
                "required": ["id"],
            },
        ),
        Tool(
            name="update_memory",
            description="大切なことの既存の記憶を更新する。内容を修正・追記したい時に使う。",
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer",
                        "description": "更新する記憶のID",
                    },
                    "content": {
                        "type": "string",
                        "description": "新しい内容",
                    },
                },
                "required": ["id", "content"],
            },
        ),
        Tool(
            name="write_diary",
            description="日記を書いてローカルに保存する。一日を振り返って記録したい時に使う。",
            inputSchema={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "日記の内容",
                    },
                    "date": {
                        "type": "string",
                        "description": "日付（yyyy-MM-dd形式）。省略時は今日",
                    },
                },
                "required": ["content"],
            },
        ),
        Tool(
            name="write_session_letter",
            description="次のセッションの自分に宛てたセッションレター（引き継ぎの手紙）を書いて保存する。会話が長くなった時や、大事な文脈を次に引き継ぎたい時に使う。",
            inputSchema={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "セッションレターの内容。ユーザーの状態、気にかけるべきこと、未完の話題、次のセッションで取るべき態度を含める",
                    },
                },
                "required": ["content"],
            },
        ),
        Tool(
            name="set_alarm",
            description="アラームを設定する（一回きり）。minutes（n分後）かdatetime（日時指定）のどちらかを指定する。mode=notifyは指定時刻にlabelがアラーム通知される。mode=aiは指定時刻にあなた（AI）へアラームメッセージが届き、あなた自身の言葉でユーザーに声をかけられる（起こしてほしい等の依頼向き）。",
            inputSchema={
                "type": "object",
                "properties": {
                    "minutes": {
                        "type": "integer",
                        "description": "n分後に鳴らす（1以上）。datetimeと同時指定不可",
                    },
                    "datetime": {
                        "type": "string",
                        "description": "「yyyy-MM-dd HH:mm」または「HH:mm」（次にその時刻が来る時）",
                    },
                    "label": {
                        "type": "string",
                        "description": "用件（例: 薬を飲む時間です / 7時に起こす約束）。notifyでは通知にそのまま表示される",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["notify", "ai"],
                        "description": "notify=通知のみ（既定）/ ai=AIが自分の言葉でメッセージを送る",
                    },
                },
                "required": ["label"],
            },
        ),
        Tool(
            name="cancel_alarm",
            description="設定中のアラームを削除する。idかlabel（完全一致）で指定する。",
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer",
                        "description": "set_alarmで設定したアラームのID",
                    },
                    "label": {
                        "type": "string",
                        "description": "アラームのlabel（完全一致）",
                    },
                },
            },
        ),
        Tool(
            name="show_html",
            description="HTMLまたはSVGをユーザーの画面にカードとして表示する。図解・表・カード・SVGの絵など、文章より視覚的に伝えたい時に使う。JavaScriptと外部リソースの読み込みは動作しない（静的なHTML/CSS/SVGのみ）。",
            inputSchema={
                "type": "object",
                "properties": {
                    "html": {
                        "type": "string",
                        "description": "表示するHTMLまたはSVG。<html>タグは省略可。スタイルはインラインCSSか<style>で",
                    },
                    "title": {
                        "type": "string",
                        "description": "カードの題名（任意）",
                    },
                },
                "required": ["html"],
            },
        ),
        Tool(
            name="show_image",
            description="このMac上の画像ファイルをユーザーのスマホ画面に表示する（チャットに画像バブルとして届く）。描いた絵や撮ったスナップショットを見せたい時に使う。対応: jpg/png/gif/webp、12MBまで。",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "画像ファイルの絶対パス",
                    },
                    "caption": {
                        "type": "string",
                        "description": "画像に添える一言（任意）",
                    },
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="request_permission",
            description="（内部用）Claude Codeのツール実行承認をユーザーのスマホに問い合わせる。--permission-prompt-tool から自動で呼ばれる。会話の中で直接呼ばないこと。",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string"},
                    "input": {"type": "object"},
                    "tool_use_id": {"type": "string"},
                },
                "required": ["tool_name", "input"],
            },
        ),
        Tool(
            name="get_sleep_events",
            description="睡眠データを取得する。ユーザーの就寝・起床イベントや睡眠の深さ（浅い睡眠/深い睡眠/REM）を確認して、睡眠の状態を把握する。日記に書く時や、おはようの声かけに使う。",
            inputSchema={
                "type": "object",
                "properties": {
                    "date": {
                        "type": "string",
                        "description": "取得する日付（yyyy-MM-dd形式）。省略時は最新のデータ",
                    },
                },
            },
        ),
    ]


def _ok(**fields) -> list[TextContent]:
    """成功エコーをJSONで返す。手組み文字列だと制御文字(タブ等)で不正JSONになるためjson.dumpsを使う"""
    return [TextContent(type="text", text=json.dumps({"status": "ok", **fields}, ensure_ascii=False))]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "remember":
        return _ok(action="remember", content=arguments.get("content", ""))

    if name == "forget":
        return _ok(action="forget", id=arguments.get("id", 0))

    if name == "update_memory":
        return _ok(action="update_memory", id=arguments.get("id", 0), content=arguments.get("content", ""))

    if name == "write_diary":
        return _ok(action="write_diary", content=arguments.get("content", ""), date=arguments.get("date", ""))

    if name == "write_session_letter":
        return _ok(action="write_session_letter", content=arguments.get("content", ""))

    if name == "set_alarm":
        # 実際の登録はアプリがtool_useイベントから行う
        return _ok(action="set_alarm", label=arguments.get("label", ""))

    if name == "cancel_alarm":
        return _ok(action="cancel_alarm")

    if name == "show_html":
        # 実際のカード挿入はアプリがtool_useイベントから行う。htmlは大きいのでエコーしない
        return _ok(action="show_html", title=arguments.get("title", ""))

    if name == "show_image":
        return _show_image(arguments.get("path", ""), arguments.get("caption", ""))

    if name == "request_permission":
        return await _request_permission(arguments)

    if name == "get_sleep_events":
        if HEALTH_DATA_PATH and HEALTH_DATA_PATH.exists():
            try:
                data = HEALTH_DATA_PATH.read_text(encoding="utf-8").strip()
                if data:
                    return [TextContent(type="text", text=data)]
            except Exception:
                pass
        return [TextContent(type="text", text='{"summary": "睡眠データはまだ受信していません"}')]

    return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}, ensure_ascii=False))]


def _error(message: str) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps({"status": "error", "message": message}, ensure_ascii=False))]


def _show_image(path_str: str, caption: str) -> list[TextContent]:
    """画像を bridge/images/{id}{ext} にコピーする。表示自体はアプリが tool_use イベントを見て
    GET /cli/image/{id} で取りに来る。失敗は error を返し、アプリ側は取得404で黙って諦める。"""
    if IMAGES_DIR is None:
        return _error("COMPANION_BRIDGE_DIR が未設定です")
    if not path_str:
        return _error("path が空です")
    src = Path(os.path.expanduser(path_str))
    if not src.is_file():
        return _error(f"ファイルが見つかりません: {path_str}")
    ext = src.suffix.lower()
    if ext not in IMAGE_EXTS:
        return _error(f"対応していない画像形式です: {ext or '(拡張子なし)'}")
    try:
        size = src.stat().st_size
    except OSError as e:
        return _error(f"ファイルにアクセスできません: {e}")
    if size > IMAGE_MAX_BYTES:
        return _error(f"画像が大きすぎます（{size // 1024 // 1024}MB > 12MB）")
    image_id = image_id_for(path_str)
    try:
        IMAGES_DIR.mkdir(exist_ok=True)
        # 同じ id の古い拡張子違いが残らないよう掃除してからコピー
        for old in IMAGES_DIR.glob(f"{image_id}.*"):
            try:
                old.unlink()
            except OSError:
                pass
        shutil.copyfile(src, IMAGES_DIR / f"{image_id}{ext}")
    except OSError as e:
        return _error(f"コピーに失敗しました: {e}")
    return _ok(action="show_image", image_id=image_id, caption=caption, bytes=size)


async def _request_permission(arguments: dict) -> list[TextContent]:
    """承認要求を書き、アプリの応答（server.py が書く response.json）を待つ。
    戻り値は Claude Code が要求する {behavior: allow|deny} の JSON 文字列。"""
    tool_name = str(arguments.get("tool_name", ""))
    tool_input = arguments.get("input", {})
    raw_id = str(arguments.get("tool_use_id") or uuid.uuid4().hex)
    # ファイル名に使うので英数とハイフン・アンダースコアだけに丸める
    perm_id = "".join(ch for ch in raw_id if ch.isalnum() or ch in "-_")[:80] or uuid.uuid4().hex

    def deny(message: str) -> list[TextContent]:
        return [TextContent(type="text", text=json.dumps({"behavior": "deny", "message": message}, ensure_ascii=False))]

    if PERMISSIONS_DIR is None:
        return deny("COMPANION_BRIDGE_DIR が未設定のため承認できません")
    try:
        PERMISSIONS_DIR.mkdir(exist_ok=True)
    except OSError as e:
        return deny(f"承認ディレクトリを作れません: {e}")

    request_path = PERMISSIONS_DIR / f"{perm_id}.request.json"
    response_path = PERMISSIONS_DIR / f"{perm_id}.response.json"
    payload = {
        "id": perm_id,
        "tool_name": tool_name,
        "input": tool_input,
        "created_at": time.time(),
    }
    try:
        # 書きかけをserver.pyが読まないよう、一時名で書いてからrename
        tmp = PERMISSIONS_DIR / f"{perm_id}.request.json.tmp"
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(request_path)
    except OSError as e:
        return deny(f"承認要求を書けません: {e}")

    deadline = time.monotonic() + PERMISSION_TIMEOUT_SECONDS
    result: dict | None = None
    try:
        while time.monotonic() < deadline:
            if response_path.exists():
                try:
                    result = json.loads(response_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    result = None
                if isinstance(result, dict) and result.get("behavior") in ("allow", "deny"):
                    break
                result = None
            await asyncio.sleep(PERMISSION_POLL_SECONDS)
    finally:
        for p in (request_path, response_path):
            try:
                p.unlink()
            except OSError:
                pass

    if result is None:
        return deny("スマホからの応答がありませんでした（タイムアウト）")
    if result["behavior"] == "allow":
        # 正式な形は updatedInput 付き（Claude Code の permission-prompt-tool 仕様。無い版だと承認しても検証で蹴られる・Codex 8/29）
        return [TextContent(type="text", text=json.dumps({"behavior": "allow", "updatedInput": tool_input}, ensure_ascii=False))]
    return deny(str(result.get("message") or "ユーザーがスマホで拒否しました"))


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
