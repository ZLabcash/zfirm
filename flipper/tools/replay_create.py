import sys, time
sys.path.insert(0, 'tools')
import flipper_cli as f
s = f.connect()
f.cmd(s, 'loader open /ext/apps/Tools/zflip.fap', 5)
time.sleep(1.5)
def k(key, kind="short", wait=0.25):
    f.cmd(s, f"input send {key} {kind}", 3); time.sleep(wait)
k("ok")
for _ in range(5): k("ok")
k("ok", "long", 0.5)
for _ in range(2):
    for _ in range(6): k("up"); k("ok")
    k("ok", "long", 0.5)
# The last long OK started the forging: stream logs now.
s.write(b"log debug\r")
out = b""
end = time.time() + float(sys.argv[1] if len(sys.argv) > 1 else 40)
try:
    while time.time() < end:
        out += s.read(4096)
except Exception as e:
    out += f"\n[serial lost: {e}]".encode()
print(out.decode(errors="replace")[-6000:])
