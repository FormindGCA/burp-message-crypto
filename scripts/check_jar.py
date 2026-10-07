"""Verify the distribution includes its entry point and private dependencies only."""
import struct
import zipfile
from pathlib import Path

path = Path("target/burp-message-crypto-0.1.0.jar")
with zipfile.ZipFile(path) as jar:
    names = set(jar.namelist())
    entry = "local/messagecrypto/MessageCryptoExtension.class"
    assert entry in names
    assert "local/messagecrypto/internal/jackson/databind/ObjectMapper.class" in names
    assert "local/messagecrypto/DemoServer.class" in names
    assert not any(name.startswith(("burp/api/", "org/mockito/", "org/junit/", "com/fasterxml/jackson/")) for name in names)
    assert struct.unpack(">H", jar.read(entry)[6:8])[0] == 61  # Java 17 class-file version
print(f"Distribution verified: {path} ({path.stat().st_size:,} bytes), Java 17, shaded JSON dependency, no bundled Burp API/test libraries.")
