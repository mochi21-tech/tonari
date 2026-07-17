"""Companion App MCP Tools Server

Claude Code の MCP サーバーとして動作し、アプリ固有のツールを提供する。
stdio トランスポートで Claude Code と通信する。

副作用系ツール（remember等）はアプリ側で stream-json の
tool_use イベントをパースして実行する。このサーバーは成功を返すだけ。
データ返却系ツール（get_sleep_events）はファイルから読み取って返す。

server.py が --mcp-config でこのサーバーを自動登録するため、
ユーザーによる手動設定は不要。
"""

import json
import os
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

BRIDGE_DIR = Path(os.environ.get("COMPANION_BRIDGE_DIR", ""))
HEALTH_DATA_PATH = BRIDGE_DIR / "health_data.json" if BRIDGE_DIR.name else None


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


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
