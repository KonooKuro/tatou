"""
rmap_routes.py
--------------
RMAP 四步握手的接口定义（Blueprint 版本）

提供两个API:
  - POST /rmap-initiate  (Step 1 -> Step 2)
  - POST /rmap-get-link  (Step 3 -> Step 4)
"""

from flask import Blueprint, request, jsonify
from pathlib import Path
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP

# ------------------------------
# 初始化 IdentityManager & RMAP
# ------------------------------
# WJJ: !!! 下面的路径要根据实际情况修改 !!!
assets = Path("/home/wjj/tatou-team2/tatou_keys")
clients_dir = assets / "client_keys"
server_pub = assets / "server_pub.asc"
server_priv = assets / "server_priv.asc"

im = IdentityManager(
    client_keys_dir=clients_dir,
    server_public_key_path=server_pub,
    server_private_key_path=server_priv,
    server_private_key_passphrase="Wjj15800593543"  # 你的服务器私钥口令
)
rmap = RMAP(im)

# ------------------------------
# Blueprint 定义
# ------------------------------
rmap_bp = Blueprint("rmap", __name__)

@rmap_bp.route("/", methods=["GET"])
def index():
    """根路由：用于测试服务是否正常运行"""
    return jsonify({
        "status": "RMAP server running",
        "endpoints": ["/rmap-initiate", "/rmap-get-link"]
    })


# ===========================================================
# Step 1 & Step 2: Client → Server (Message1)，Server → Client (Response1)
# ===========================================================
@rmap_bp.route("/rmap-initiate", methods=["POST"])
def rmap_initiate():
    """
    Step 1: 客户端 → 服务器
      - 客户端发送 {nonceClient, identity}，用服务器公钥加密
    Step 2: 服务器 → 客户端
      - 服务器生成 nonceServer
      - 返回 {nonceServer}，用客户端公钥加密
    """
    try:
        msg1 = request.get_json()
        resp1 = rmap.handle_message1(msg1)
        return jsonify(resp1)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ===========================================================
# Step 3 & Step 4: Client → Server (Message2)，Server → Client (Result)
# ===========================================================
@rmap_bp.route("/rmap-get-link", methods=["POST"])
def rmap_get_link():
    """
    Step 3: 客户端 → 服务器
      - 客户端发送 {nonceClient, nonceServer}，用服务器公钥加密
    Step 4: 服务器 → 客户端
      - 服务器验证 nonces
      - 拼接 (nonceClient << 64) | nonceServer
      - 返回 result (32位16进制字符串)
    """
    try:
        msg2 = request.get_json()
        resp2 = rmap.handle_message2(msg2)
        return jsonify(resp2)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
