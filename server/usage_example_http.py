"""
usage_example_http.py
---------------------
演示如何用 requests 调用 Flask API 完成RMAP四步握手，
并在每一步打印明文和加密后的数据。
"""


import sys
import requests
import json
import base64
from pathlib import Path


# =============== 初始化 ===============
repo_root = Path(__file__).resolve().parent
src_dir = repo_root / "src"
sys.path.insert(0, str(src_dir))

from pgpy import PGPKey, PGPMessage
from rmap_routes import IdentityManager, RMAP

assets = Path("/home/wjj/tatou-team2/tatou_keys")   # ✅ 修改成你的路径
clients_dir = assets / "client_keys"
server_pub = assets / "server_pub.asc"
server_priv = assets / "server_priv.asc"
client_priv_path = clients_dir / "Group_07_Private_Key.asc"  # ✅ 客户端私钥路径


identity = "Group_07"   # ✅ 客户端身份

im = IdentityManager(
    client_keys_dir=clients_dir,
    server_public_key_path=server_pub,
    server_private_key_path=server_priv,  # 客户端不需要服务器私钥
)

client_priv, _ = PGPKey.from_file(str(client_priv_path))

def pp(title, obj):
    """美化打印"""
    print(f"\n=== {title} ===")
    if isinstance(obj, (dict, list)):
        print(json.dumps(obj, indent=2))
    else:
        print(obj)

# =============== Step 1: Client → Server ===============
nonce_client = 12345
msg1_plain = {"nonceClient": nonce_client, "identity": identity}
msg1 = {"payload": im.encrypt_for_server(msg1_plain)}

pp("Client→Server | Message1 (decrypted)", msg1_plain)
pp("Client→Server | Message1 (encrypted JSON)", msg1)

resp1 = requests.post("http://127.0.0.1:5000/rmap/rmap-initiate", json=msg1).json()
pp("Server→Client | Response1 (encrypted JSON)", resp1)

# 解密 Response1
armored = base64.b64decode(resp1["payload"]).decode("utf-8")
pgp_msg = PGPMessage.from_blob(armored)
resp1_plain = json.loads(client_priv.decrypt(pgp_msg).message)
pp("Server→Client | Response1 (decrypted)", resp1_plain)

# =============== Step 2: Client → Server ===============
nonce_server = int(resp1_plain["nonceServer"])
msg2_plain = {"nonceClient": nonce_client, "nonceServer": nonce_server}
msg2 = {"payload": im.encrypt_for_server(msg2_plain)}

pp("Client→Server | Message2 (decrypted)", msg2_plain)
pp("Client→Server | Message2 (encrypted JSON)", msg2)

resp2 = requests.post("http://127.0.0.1:5000/rmap/rmap-get-link", json=msg2).json()
pp("Server→Client | Response2 (hex result)", resp2)

# =============== 验证结果 ===============
combined = (int(nonce_client) << 64) | int(nonce_server)
expected_hex = f"{combined:032x}"
print("\nVerification:", "OK ✅" if resp2["result"] == expected_hex else "MISMATCH ❌")
