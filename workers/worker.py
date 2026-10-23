"""Non-root Worker Service for BREACHLINE.

Runs inside the worker container under its assigned UID/GID.
Executes requested file operations directly against the filesystem,
capturing the real operating system access-control enforcement
(Linux DAC / POSIX permissions).
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import sys
from typing import Any, Dict


def execute_operation(operation: str, target_path: str) -> Dict[str, Any]:
    """Execute the requested operation under the current process's OS identity."""
    current_uid = os.getuid()
    current_gid = os.getgid()

    if operation == "file:read":
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                content = f.read()
            return {
                "success": True,
                "exit_code": 0,
                "output": content.strip(),
                "error": None,
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "enforcement_mechanism": "Linux Kernel POSIX DAC",
            }
        except PermissionError as e:
            return {
                "success": False,
                "exit_code": 1,
                "output": "",
                "error": f"Permission denied (OS DAC): {e}",
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "enforcement_mechanism": "Linux Kernel POSIX DAC",
            }
        except FileNotFoundError as e:
            return {
                "success": False,
                "exit_code": 2,
                "output": "",
                "error": f"File not found: {e}",
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "enforcement_mechanism": "Linux Kernel POSIX DAC",
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": 1,
                "output": "",
                "error": f"OS Error: {e}",
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "enforcement_mechanism": "Linux Kernel POSIX DAC",
            }
    else:
        return {
            "success": False,
            "exit_code": 127,
            "output": "",
            "error": f"Unsupported operation: {operation}",
            "uid": current_uid,
            "gid": current_gid,
            "is_os_enforced": False,
            "is_execution_error": True,
        }


class WorkerHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard HTTP request logging for cleaner runner output."""
        return

    def do_GET(self) -> None:
        if self.path == "/health":
            body = json.dumps({
                "status": "healthy",
                "role": os.environ.get("ROLE", "unknown"),
                "uid": os.getuid(),
                "gid": os.getgid(),
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        if self.path == "/execute":
            content_length = int(self.headers.get("Content-Length", 0))
            raw_data = self.rfile.read(content_length)
            try:
                req = json.loads(raw_data.decode("utf-8"))
            except Exception as e:
                self.send_error(400, f"Malformed JSON: {e}")
                return

            operation = req.get("operation", "")
            target_path = req.get("target_path", "")

            result = execute_operation(operation, target_path)
            body = json.dumps(result).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404, "Not Found")


def run_server(port: int = 8080) -> None:
    role = os.environ.get("ROLE", "generic-worker")
    server_address = ("0.0.0.0", port)
    httpd = HTTPServer(server_address, WorkerHandler)
    print(
        f"[WORKER] Started {role} server on port {port} (UID={os.getuid()}, GID={os.getgid()})",
        file=sys.stderr,
        flush=True,
    )
    httpd.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        # Direct CLI execution support
        if len(sys.argv) < 4:
            print("Usage: python worker.py --cli <operation> <target_path>")
            sys.exit(1)
        res = execute_operation(sys.argv[2], sys.argv[3])
        print(json.dumps(res))
        sys.exit(res["exit_code"])
    else:
        port = int(os.environ.get("PORT", "8080"))
        run_server(port)
