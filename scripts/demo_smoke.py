"""Exercise the packaged synthetic server over loopback HTTP, without Burp."""
import socket
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

jar = Path("target/burp-message-crypto-0.1.0.jar").resolve()
sample = subprocess.check_output(["java", "-cp", str(jar), "local.messagecrypto.DemoServer", "--sample"], text=True)
body = sample.split("\n\n", 1)[1].strip()
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
process = subprocess.Popen(["java", "-cp", str(jar), "local.messagecrypto.DemoServer", str(port)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
try:
    deadline = time.monotonic() + 10
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            if process.poll() is not None or time.monotonic() > deadline:
                raise AssertionError("Synthetic server failed to start")
            time.sleep(0.1)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(f"http://127.0.0.1:{port}/MessageHandler", data=body.encode(),
                                     headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
    with opener.open(request, timeout=5) as response:
        xml = response.read().decode()
        assert response.status == 200
        assert "<Status>ok</Status>" in xml
        assert urllib.parse.parse_qs(body)["password"][0] in xml
    print("Packaged synthetic HTTP password/response round-trip passed.")
finally:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    process.stderr.close()
