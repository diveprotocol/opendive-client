import base64
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from dive.keys import generate_base64_keypair

keys = generate_base64_keypair()

raw_private = base64.b64decode(keys["private_key"])
raw_public = base64.b64decode(keys["public_key"])

combined_binary = raw_private + raw_public
full_private_base64 = base64.b64encode(combined_binary).decode("utf-8")

print("alg:", keys["algorithm"])
print("public:", keys["public_key"])
print("private:", full_private_base64)
