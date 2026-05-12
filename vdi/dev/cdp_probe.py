"""Minimal CDP harness for iter-3 development.

Launches Chrome with the local extension loaded, opens chrome://extensions
to coerce the SW awake, then connects to its service worker target and
captures console output for N seconds.

Usage:
    python vdi/dev/cdp_probe.py [--seconds 8]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import websockets

CHROME_BIN = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
EXT_DIR = str(Path(__file__).resolve().parents[1] / "extension")
PROFILE_DIR = "/tmp/pw-relay-test-profile"
DEBUG_PORT = 9222


def http_get_json(url: str, retries: int = 30, delay: float = 0.3):
    last_err = None
    for _ in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                return json.loads(r.read())
        except Exception as e:
            last_err = e
            time.sleep(delay)
    raise RuntimeError(f"failed to fetch {url}: {last_err}")


async def cdp_call(ws, msg_id, method, params=None):
    await ws.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))
    while True:
        raw = await ws.recv()
        msg = json.loads(raw)
        if msg.get("id") == msg_id:
            return msg


async def trigger_extension_via_browser(seconds: float) -> int:
    # Connect to the browser-wide CDP endpoint to enumerate all targets.
    version = http_get_json(f"http://127.0.0.1:{DEBUG_PORT}/json/version")
    browser_ws = version["webSocketDebuggerUrl"]
    print(f"[probe] browser ws: {browser_ws}")
    async with websockets.connect(browser_ws, max_size=10_000_000) as bws:
        # Open chrome://extensions to force the extension subsystem to enumerate.
        r = await cdp_call(bws, 100, "Target.createTarget", {"url": "chrome://extensions/"})
        ext_target = r["result"]["targetId"]
        print(f"[probe] opened chrome://extensions target={ext_target}")
        await asyncio.sleep(1.5)

        # List all targets via the HTTP /json endpoint after the wake-up.
        all_targets = http_get_json(f"http://127.0.0.1:{DEBUG_PORT}/json")
        print(f"[probe] {len(all_targets)} targets after wakeup:")
        sw_url = None
        ext_id = None
        for t in all_targets:
            print(f"  - type={t.get('type'):14} url={t.get('url')}")
            if t.get("type") == "service_worker" and "chrome-extension://" in (t.get("url") or ""):
                # Filter for our extension by name match in URL is hard since
                # ID is hash-of-path. Take any extension SW for now.
                sw_url = t["webSocketDebuggerUrl"]
                u = t["url"]
                ext_id = u.split("//")[1].split("/")[0]

        # Also attach to chrome://extensions tab and read which extensions are listed.
        ext_page = next((t for t in all_targets if t.get("type") == "page" and "chrome://extensions" in (t.get("url") or "")), None)
        if ext_page:
            async with websockets.connect(ext_page["webSocketDebuggerUrl"], max_size=10_000_000) as pws:
                await cdp_call(pws, 1, "Runtime.enable")
                await cdp_call(pws, 2, "DOM.enable")
                # Use Runtime.evaluate on the chrome://extensions Polymer DOM to list extensions.
                eval_msg = await cdp_call(pws, 3, "Runtime.evaluate", {
                    "expression": """
                        (async () => {
                          // chrome://extensions exposes a custom element <extensions-manager>
                          // with a shadow DOM. Walk it to read all extension items.
                          const mgr = document.querySelector('extensions-manager');
                          if (!mgr) return {error: 'no extensions-manager'};
                          const list = mgr.shadowRoot.querySelector('extensions-item-list');
                          if (!list) return {error: 'no extensions-item-list'};
                          const items = list.shadowRoot.querySelectorAll('extensions-item');
                          const out = [];
                          items.forEach(it => {
                            const id = it.id;
                            const name = it.shadowRoot.querySelector('#name')?.textContent?.trim();
                            const desc = it.shadowRoot.querySelector('#description')?.textContent?.trim();
                            const enabled = it.shadowRoot.querySelector('cr-toggle')?.checked;
                            const errors = Array.from(it.shadowRoot.querySelectorAll('.error-message')).map(e => e.textContent.trim());
                            out.push({id, name, desc, enabled, errors});
                          });
                          return out;
                        })()
                    """,
                    "awaitPromise": True,
                    "returnByValue": True,
                })
                result = eval_msg["result"]["result"].get("value")
                print(f"[probe] extensions found via DOM: {json.dumps(result, indent=2)}")

        if not sw_url:
            print("[probe] no service worker for any extension; trying to coerce it...")
            # Find our extension's ID, then open one of its URLs to wake the SW.
            # Without a deterministic key in the manifest, we don't know our ID a priori,
            # but the DOM probe should have given it.
            return 3

        async with websockets.connect(sw_url, max_size=10_000_000) as sws:
            await cdp_call(sws, 1, "Runtime.enable")
            await cdp_call(sws, 2, "Log.enable")
            print(f"[probe] connected to SW ({ext_id}); capturing for {seconds}s")
            deadline = asyncio.get_event_loop().time() + seconds
            while True:
                t = deadline - asyncio.get_event_loop().time()
                if t <= 0:
                    break
                try:
                    raw = await asyncio.wait_for(sws.recv(), timeout=t)
                except asyncio.TimeoutError:
                    break
                msg = json.loads(raw)
                m = msg.get("method")
                if m == "Runtime.consoleAPICalled":
                    p = msg["params"]
                    rendered = " ".join(a.get("value", a.get("description", "?")) for a in p.get("args", []))
                    print(f"[sw {p.get('type','log')}] {rendered}")
                elif m == "Runtime.exceptionThrown":
                    ex = msg["params"].get("exceptionDetails", {})
                    print(f"[sw exception] {ex.get('text')} :: {ex.get('exception', {}).get('description')}")
                elif m == "Log.entryAdded":
                    entry = msg["params"]["entry"]
                    print(f"[sw log {entry.get('level')}] {entry.get('text')}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=6.0)
    ap.add_argument("--keep-profile", action="store_true")
    args = ap.parse_args()

    # Kill any stragglers from a prior run.
    subprocess.run(["pkill", "-f", "pw-relay-test-profile"], check=False)
    time.sleep(0.5)
    if not args.keep_profile and os.path.isdir(PROFILE_DIR):
        shutil.rmtree(PROFILE_DIR)

    cmd = [
        CHROME_BIN,
        f"--user-data-dir={PROFILE_DIR}",
        f"--remote-debugging-port={DEBUG_PORT}",
        f"--load-extension={EXT_DIR}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=DialMediaRouteProvider",
        "--window-position=-2000,-2000",
        "--window-size=900,600",
        "about:blank",
    ]
    print("[probe] launching:", " ".join(cmd))
    chrome = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        http_get_json(f"http://127.0.0.1:{DEBUG_PORT}/json/version")
        rc = asyncio.run(trigger_extension_via_browser(args.seconds))
    finally:
        chrome.send_signal(signal.SIGTERM)
        try:
            chrome.wait(timeout=5)
        except subprocess.TimeoutExpired:
            chrome.kill()
    sys.exit(rc)


if __name__ == "__main__":
    main()
