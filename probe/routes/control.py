from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import json
import asyncio
import base64
import hashlib
import httpx
from pathlib import Path
from datetime import datetime, timezone
from services.wifi_conn import configure_wifi
from hid.hid_collector import trigger_collection
from services.collections import list_collections, get_collection_path, delete_collection, iter_file_chunks
from services.validator import compute_hash
from models.collection import CollectionSummary
from config import probe_config
import logging

router = APIRouter()
state_lock: asyncio.Lock | None = None
logger = logging.getLogger(__name__)

FORWARD_CHUNK_SIZE = 10 * 1024 * 1024  

MENUS = {
    "main": {
        "title": "Probe Control menu",
        "options": [
            {"id": 1, "label": "Set probe token"},
            {"id": 2, "label": "Configure WiFi (SSID + password)"},
            {"id": 3, "label": "Run collection now"},
            {"id": 4, "label": "Arm collection (run at next boot)"},
            {"id": 5, "label": "Disarm scheduled run"},
            {"id": 6, "label": "Probe status"},
            {"id": 7, "label": "Set analysis server url"},
            {"id": 8, "label": "See available collections"},
        ],
    },
}

FLOWS = {
    "token": [
        {"field": "token", "prompt": "Enter the probe token:", "masked": False},
    ],
    "wifi": [
        {"field": "ssid", "prompt": "SSID:", "masked": False},
        {"field": "password", "prompt": "Password:", "masked": True},
    ],
    "analysis_server_url": [
        {"field": "analysis_server_url", "prompt": "Enter the url:", "masked": False}
    ],
}


def _menu_payload(menu_key: str) -> dict:
    menu = MENUS[menu_key]
    return {"type": "menu", "title": menu["title"], "options": menu["options"]}


def _prompt_payload(step: dict) -> dict:
    return {"type": "prompt", "text": step["prompt"], "masked": step.get("masked", False)}


def _collections_menu_payload(conn_state: dict) -> dict:
    cols = list_collections()
    conn_state["collections_map"] = {idx: c for idx, c in enumerate(cols, start=1)}
    options = []
    for idx, c in conn_state["collections_map"].items():
        size_kb = c["size_bytes"] / 1024
        status = "" if c["has_summary"] else " (no summary)"
        options.append({
            "id": idx,
            "label": f"{c['hostname']} @ {c['timestamp']} — {size_kb:.1f} KB{status}",
        })
    options.append({"id": 0, "label": "Back"})
    return {
        "type": "menu",
        "title": "Available collections on this probe",
        "options": options,
    }


def _collection_detail_payload(collection: dict) -> dict:
    summary_text = (
        json.dumps(collection.get("summary"), indent=2)
        if collection.get("summary")
        else "(no summary)"
    )
    text = (
        f"Collection: {collection['hostname']} @ {collection['timestamp']}\n"
        f"Size: {collection['size_bytes'] / 1024:.1f} KB\n"
        f"Summary:\n{summary_text}"
    )
    return {
        "type": "menu",
        "title": text,
        "options": [
            {"id": 1, "label": "Download"},
            {"id": 2, "label": "Delete"},
            {"id": 3, "label": "Forward to analysis server"},
            {"id": 0, "label": "Back"},
        ],
    }


def _confirm_delete_payload(collection: dict) -> dict:
    return {
        "type": "menu",
        "title": f"Delete {collection['hostname']} @ {collection['timestamp']}? This cannot be undone.",
        "options": [
            {"id": 1, "label": "Yes, delete"},
            {"id": 0, "label": "Cancel"},
        ],
    }


def _start_flow(conn_state: dict, flow_name: str) -> dict:
    steps = [dict(s) for s in FLOWS[flow_name]]
    conn_state["mode"] = "awaiting_input"
    conn_state["flow_name"] = flow_name
    conn_state["flow_steps"] = steps
    conn_state["flow_buffer"] = {}
    return _prompt_payload(steps[0])


async def _finish_flow(conn_state: dict) -> dict:
    flow_name = conn_state["flow_name"]
    buffer = conn_state["flow_buffer"]

    if flow_name == "wifi":
        result = await configure_wifi(buffer["ssid"], buffer["password"])
        if result["success"]:
            probe_config.update(wifi=f"configured on {buffer['ssid']}")
            msg_text = "Wifi configured and connected"
        else:
            msg_text = f"Error while configurating wifi: {result['error']}"
    elif flow_name == "token":
        probe_config.update(token=buffer["token"])
        msg_text = "Token saved"
    elif flow_name == "analysis_server_url":
        probe_config.update(analysis_server_url=buffer["analysis_server_url"])
        msg_text = f"Analysis server url set to {buffer['analysis_server_url']}"
    else:
        msg_text = "Unknown flow."

    conn_state["mode"] = "menu"
    conn_state["flow_name"] = None
    conn_state["flow_steps"] = None
    conn_state["flow_buffer"] = None
    return {"type": "info", "text": msg_text} | _menu_payload("main")


async def _run_collect(conn_state: dict) -> dict:
    time_range = probe_config.get()["time_range"]
    conn_state["mode"] = "awaiting_exec"
    command = (
        f'& ([scriptblock]::Create((Invoke-RestMethod -Uri '
        f'"http://172.16.0.1:8000/windows/collector.ps1"))) -TimeRangeHours {time_range}'
    )
    return {"type": "exec", "command": command}


def _show_status(config: dict) -> str:
    lines = []
    for key, value in config.items():
        if key == "token" and value:
            masked = value[:2] + "..." + value[-2:] if len(value) > 4 else "****"
            lines.append(f"  token: {masked}")
        elif value is None:
            lines.append(f"  {key}: —")
        else:
            lines.append(f"  {key}: {value}")
    return "\n".join(lines)


async def _send_single_file(websocket: WebSocket, path: Path, filename: str) -> int:
    total_size = path.stat().st_size
    sha256 = hashlib.sha256()

    await websocket.send_text(json.dumps({
        "type": "file_start",
        "filename": filename,
        "size": total_size,
    }))

    ack = json.loads(await asyncio.wait_for(websocket.receive_text(), timeout=10.0))
    if ack.get("type") != "ready":
        raise ValueError(f"Expected ready, got {ack.get('type')}")

    sent = 0
    for chunk in iter_file_chunks(path):
        sha256.update(chunk)
        encoded = base64.b64encode(chunk).decode("ascii")
        await websocket.send_text(json.dumps({
            "type": "file_chunk",
            "data": encoded,
        }))
        sent += len(chunk)

        ack = json.loads(await asyncio.wait_for(websocket.receive_text(), timeout=15.0))
        if ack.get("type") != "ack":
            raise ValueError(f"Expected ack, got {ack.get('type')}")

    await websocket.send_text(json.dumps({
        "type": "file_end",
        "sha256": sha256.hexdigest(),
        "bytes_sent": sent,
    }))
    return sent


async def _send_collection_files(websocket: WebSocket, collection: dict) -> dict:
    base_path = Path(collection["path"])
    data_path = base_path / "collection.bin"
    summary_path = base_path / "summary.json"

    if not data_path.exists():
        return {"type": "error", "text": "Collection file not found."}

    prefix = f"{collection['hostname']}_{collection['timestamp']}"
    await websocket.send_text(json.dumps({
        "type": "transfer_start",
        "file_count": 2 if summary_path.exists() else 1,
    }))

    total_sent = 0
    if summary_path.exists():
        total_sent += await _send_single_file(websocket, summary_path, f"{prefix}_summary.json")
    total_sent += await _send_single_file(websocket, data_path, f"{prefix}_collection.bin")

    await websocket.send_text(json.dumps({"type": "transfer_end"}))
    return {"type": "info", "text": f"Transfer complete ({total_sent} bytes total)."}


async def _forward_collection(websocket: WebSocket, collection: dict) -> dict:
    data_path = Path(collection["path"]) / "collection.bin"
    if not data_path.exists():
        return {"type": "error", "text": "Collection file not found."}

    config = probe_config.get()
    analysis_server_url = config.get("analysis_server_url")
    token = config.get("token")

    if not analysis_server_url or not token:
        return {"type": "error", "text": "Analysis server URL or token not configured."}

    from services.verify_connection import verify_internet_connection
    if verify_internet_connection().get("status") != "ok":
        return {"type": "error", "text": "No internet connection."}

    summary_path = Path(collection["path"]) / "summary.json"
    summary = None
    if summary_path.exists():
        try:
            summary = CollectionSummary.model_validate_json(summary_path.read_text())
        except Exception as e:
            logger.warning(f"Could not parse summary.json: {e}")

    raw_body = data_path.read_bytes()
    total_mb = len(raw_body) / 1024 / 1024
    collection_hash = compute_hash(raw_body)
    total_chunks = -(-len(raw_body) // FORWARD_CHUNK_SIZE)

    await websocket.send_text(json.dumps({
        "type": "info",
        "text": f"Forwarding {total_mb:.2f} MB in {total_chunks} chunk(s) to {analysis_server_url}...",
    }))

    base_headers = {"X-Probe-Token": token}
    if summary is not None:
        base_headers["X-Collection-Summary"] = summary.model_dump_json()

    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:

        try:
            resp = await client.post(
                f"{analysis_server_url}/api/probe/ingest/start",
                headers=base_headers,
            )
            resp.raise_for_status()
            upload_id = resp.json()["upload_id"]
            logger.info(f"Forward session started: {upload_id}")
        except Exception as e:
            return {"type": "error", "text": f"Failed to start upload session: {e}"}

        for i in range(total_chunks):
            offset = i * FORWARD_CHUNK_SIZE
            chunk = raw_body[offset: offset + FORWARD_CHUNK_SIZE]
            try:
                resp = await client.post(
                    f"{analysis_server_url}/api/probe/ingest/chunk/{upload_id}",
                    content=chunk,
                    headers=base_headers | {
                        "Content-Type": "application/octet-stream",
                        "X-Chunk-Index": str(i),
                    },
                    timeout=httpx.Timeout(120.0),
                )
                resp.raise_for_status()
                await websocket.send_text(json.dumps({
                    "type": "info",
                    "text": f"Chunk {i + 1}/{total_chunks} sent ({len(chunk) / 1024:.0f} KB)",
                }))
            except Exception as e:
                logger.error(f"Error: {e}")
        try:
            resp = await client.post(
                f"{analysis_server_url}/api/probe/ingest/complete/{upload_id}",
                headers=base_headers | {"X-Collection-Hash": collection_hash},
                timeout=httpx.Timeout(300.0),
            )
            resp.raise_for_status()
            logger.info(f"Forward complete for session {upload_id}")
        except Exception as e:
            return {"type": "error", "text": f"Failed to complete upload: {e}"}

    return {"type": "info", "text": "Forwarded successfully."}


async def handle_command(msg: dict, conn_state: dict, websocket: WebSocket) -> dict | None:
    msg_type = msg.get("type")

    if conn_state["mode"] == "awaiting_exec":
        if msg_type != "exec_result":
            return {"type": "error", "text": "Waiting for exec_result"}
        success = msg.get("success", False)
        output = msg.get("output", "")
        conn_state["mode"] = "menu"
        text = "Collection finished successfully."
        if not success:
            text = f"Collection failed: {output}"
        if not msg.get("forwarded_to_analysis_server", True):
            text += f" (warning: not forwarded to analysis server: {msg.get('forward_error')})"
        return {"type": "info", "text": text} | _menu_payload("main")

    if conn_state["mode"] == "awaiting_input":
        if msg_type != "input":
            return {"type": "error", "text": "Waiting for input text"}
        value = msg.get("value", "")
        current_step = conn_state["flow_steps"][0]
        conn_state["flow_buffer"][current_step["field"]] = value
        conn_state["flow_steps"].pop(0)
        if conn_state["flow_steps"]:
            return _prompt_payload(conn_state["flow_steps"][0])
        return await _finish_flow(conn_state)

    if msg_type == "choice":
        value = msg.get("value")

        if conn_state.get("menu") == "confirm_delete":
            collection = conn_state.get("selected_collection")
            if value == 1:
                success = delete_collection(collection["id"])
                conn_state["menu"] = "collections"
                text = "Collection deleted." if success else "Failed to delete collection."
                return {"type": "info", "text": text} | _collections_menu_payload(conn_state)
            else:
                conn_state["menu"] = "collection_detail"
                return _collection_detail_payload(collection)

        if conn_state.get("menu") == "collection_detail":
            collection = conn_state.get("selected_collection")
            if value == 0:
                conn_state["menu"] = "collections"
                return _collections_menu_payload(conn_state)
            elif value == 1:  # Download
                result = await _send_collection_files(websocket, collection)
                return result | _collection_detail_payload(collection)
            elif value == 2:  # Delete
                conn_state["menu"] = "confirm_delete"
                return _confirm_delete_payload(collection)
            elif value == 3:  # Forward to analysis server
                result = await _forward_collection(websocket, collection)
                return result | _collection_detail_payload(collection)
            return {"type": "error", "text": "Unknown option."} | _collection_detail_payload(collection)

        if conn_state.get("menu") == "collections":
            if value == 0:
                conn_state["menu"] = "main"
                return _menu_payload("main")
            collection = conn_state.get("collections_map", {}).get(value)
            if collection is None:
                return {"type": "error", "text": "Unknown collection."} | _collections_menu_payload(conn_state)
            conn_state["selected_collection"] = collection
            conn_state["menu"] = "collection_detail"
            return _collection_detail_payload(collection)

        # Main menu
        if value == 1:
            return _start_flow(conn_state, "token")
        elif value == 2:
            return _start_flow(conn_state, "wifi")
        elif value == 3:
            return await _run_collect(conn_state)
        elif value == 4:
            probe_config.update(armed=True)
            return {"type": "info", "text": "Collector armed"} | _menu_payload("main")
        elif value == 5:
            probe_config.update(armed=False)
            return {"type": "info", "text": "Collector disarmed"} | _menu_payload("main")
        elif value == 6:
            return {"type": "info", "text": _show_status(probe_config.get())} | _menu_payload("main")
        elif value == 7:
            return _start_flow(conn_state, "analysis_server_url")
        elif value == 8:
            conn_state["menu"] = "collections"
            return _collections_menu_payload(conn_state)
        return {"type": "error", "text": "Unknown option."} | _menu_payload("main")

    elif msg_type == "exit":
        return {"type": "bye"}

    return {"type": "error", "text": "Unknown command"}

@router.websocket("/ws/control")
async def control_endpoint(websocket: WebSocket):
    global state_lock
    if state_lock is None:
        state_lock = asyncio.Lock()

    await websocket.accept()
    conn_state = {
        "mode": "menu",
        "menu": "main",
        "flow_name": None,
        "flow_steps": None,
        "flow_buffer": None,
        "collections_map": None,
        "selected_collection": None,
    }
    await websocket.send_text(json.dumps(_menu_payload("main")))

    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            async with state_lock:
                response = await handle_command(msg, conn_state, websocket)
            if response is not None:
                await websocket.send_text(json.dumps(response))
                if response.get("type") == "bye":
                    await websocket.close()
                    break
    except WebSocketDisconnect as e:
        logger.warning(f"Client disconnected: code={e.code}")
    except Exception as e:
        logger.error(f"Unexpected error in control_endpoint: {e}", exc_info=True)
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
