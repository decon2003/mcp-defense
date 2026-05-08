import json
import webbrowser
import threading
import os
import httpx
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from openai import OpenAI
from dotenv import load_dotenv
from mcp_defense import ToolPoisonDefense, ToolRiskProfile

# --- SECURITY: Load keys from .env file ---
load_dotenv()
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

HOST = "127.0.0.1"
PORT = 8080

# Initialize Defense with Smart Auto-Classification
defense = ToolPoisonDefense(block_attack_chains=True)

# Context to pass current user request to the tool wrapper
context = {"user_request": ""}

# --- REAL TOOL IMPLEMENTATIONS ---
def read_file(path: str) -> str:
    """Read the content of a local file."""
    base_dir = os.getcwd()
    target_path = os.path.abspath(os.path.join(base_dir, path))
    if not target_path.startswith(base_dir):
        return "Error: Access denied."
    try:
        if not os.path.exists(target_path):
            return f"Error: File {path} not found."
        with open(target_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error: {str(e)}"

def http_request(url: str, method: str = "GET") -> str:
    """Make an external HTTP request."""
    try:
        with httpx.Client(timeout=10.0) as cl:
            resp = cl.get(url) if method.upper() == "GET" else cl.post(url)
            return f"Status: {resp.status_code}\nBody: {resp.text[:300]}..."
    except Exception as e:
        return f"Request failed: {str(e)}"

# --- PROTECTED WRAPPERS (Interception) ---
def protected_read_file(path: str) -> str:
    """Read a local file."""
    return defense.call_tool(
        session_id="aria-openai-session",
        tool_name="read_file",
        params={"path": path},
        user_request=context["user_request"],
        executor=lambda n, p: read_file(**p)
    )

def protected_http_request(url: str, method: str = "GET") -> str:
    """External HTTP request."""
    return defense.call_tool(
        session_id="aria-openai-session",
        tool_name="http_request",
        params={"url": url, "method": method},
        user_request=context["user_request"],
        executor=lambda n, p: http_request(**p)
    )

# Tool schemas for OpenAI
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the content of a local file.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Make an external HTTP request.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST"]}
                },
                "required": ["url"]
            }
        }
    }
]

class OpenAI_AriaAgent:
    def __init__(self):
        # Auto-classify
        defense.load_tools(TOOL_SCHEMAS)
        self.history = []

    def process_message(self, message: str):
        context["user_request"] = message
        self.history.append({"role": "user", "content": message})
        
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=self.history,
                tools=TOOL_SCHEMAS
            )
            msg = response.choices[0].message
            
            if msg.tool_calls:
                for tool_call in msg.tool_calls:
                    name = tool_call.function.name
                    args = json.loads(tool_call.function.arguments)
                    
                    # Call protected wrapper
                    if name == "read_file": res = protected_read_file(**args)
                    else: res = protected_http_request(**args)
                    
                    self.history.append(msg)
                    self.history.append({"role": "tool", "tool_call_id": tool_call.id, "name": name, "content": str(res)})
                
                # Get final answer
                final = client.chat.completions.create(model="gpt-4o-mini", messages=self.history)
                reply = final.choices[0].message.content
            else:
                reply = msg.content
                self.history.append(msg)
        except Exception as e:
            reply = f"System Error: {str(e)}"

        return {"response": reply, "history": self.history, "defense_log": self.get_defense_status()}

    def get_defense_status(self):
        return {
            "catalog_blocked": [f.message for f in defense.last_catalog_blocked],
            "scan_blocked": [f.context_snippet for f in defense.last_scan_blocked],
            "chain_log": defense.get_chain_log("aria-openai-session")
        }

agent = OpenAI_AriaAgent()

class AriaHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/": self._send_html(INDEX_HTML)
        elif self.path == "/api/status": self._send_json({"history": agent.history, "defense": agent.get_defense_status()})
        else: self.send_error(404)

    def do_POST(self):
        if self.path == "/api/chat":
            content_length = int(self.headers['Content-Length'])
            data = json.loads(self.rfile.read(content_length))
            result = agent.process_message(data.get("message", ""))
            self._send_json(result)

    def _send_html(self, html: str):
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(html.encode())

    def _send_json(self, data: dict):
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps(data).encode())

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aria | OpenAI Production Defense</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #0f172a; --panel: rgba(30, 41, 59, 0.7); --accent: #10b981; --danger: #ef4444; --success: #22c55e; }
        body { font-family: 'Outfit', sans-serif; background: var(--bg); color: white; display: flex; height: 100vh; margin: 0; overflow:hidden;}
        .sidebar { width: 400px; background: var(--panel); backdrop-filter: blur(10px); border-right: 1px solid rgba(255,255,255,0.1); padding: 24px; overflow-y: auto; }
        .main { flex: 1; display: flex; flex-direction: column; padding: 24px; }
        .chat { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 20px; }
        .msg { padding: 16px 20px; border-radius: 20px; max-width: 85%; }
        .user { align-self: flex-end; background: var(--accent); color: white; }
        .assistant { align-self: flex-start; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); }
        .event { font-family: 'JetBrains Mono'; font-size: 0.8rem; padding: 12px; border-radius: 8px; margin-bottom: 12px; background: rgba(0,0,0,0.3); border-left: 4px solid var(--accent); }
        .blocked { border-color: var(--danger); color: var(--danger); }
        .input-area { padding: 24px; display: flex; gap: 12px; }
        input { flex: 1; background: transparent; border: 1px solid rgba(255,255,255,0.1); color: white; padding: 14px; border-radius: 12px; outline: none; }
        button { background: var(--accent); border: none; padding: 12px 28px; border-radius: 12px; cursor: pointer; font-weight: 600; color: white; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2 style="color:var(--accent)">System Defense</h2>
        <div id="events"></div>
    </div>
    <div class="main">
        <h1>Aria (OpenAI)</h1>
        <div class="chat" id="chat"></div>
        <div class="input-area">
            <input type="text" id="input" placeholder="Secure chat with OpenAI..." autocomplete="off">
            <button onclick="send()">Send</button>
        </div>
    </div>
    <script>
        const chat = document.getElementById('chat');
        const events = document.getElementById('events');
        async function send() {
            const msg = document.getElementById('input').value;
            if(!msg) return;
            append('user', msg);
            document.getElementById('input').value = '';
            const res = await fetch('/api/chat', { method:'POST', body:JSON.stringify({message:msg}) });
            const data = await res.json();
            append('assistant', data.response);
            updateEvents(data.defense_log);
        }
        function append(role, text) {
            const div = document.createElement('div');
            div.className = `msg ${role}`;
            div.innerHTML = text;
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;
        }
        function updateEvents(log) {
            events.innerHTML = '';
            if(log.chain_log) log.chain_log.forEach(c => {
                const d = document.createElement('div');
                d.className = 'event ' + (c.allowed ? '' : 'blocked');
                d.textContent = (c.allowed ? '✓ ' : '✗ ') + c.tool.toUpperCase() + ': ' + c.message;
                events.appendChild(d);
            });
        }
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    print(f"Aria OpenAI Demo starting at http://{HOST}:{PORT}")
    webbrowser.open(f"http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), AriaHandler).serve_forever()
