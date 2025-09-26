"""
identity_manager.py
-------------------
管理密钥加载 & 加解密
"""

import base64
import json
from pathlib import Path
from pgpy import PGPKey, PGPMessage


class IdentityManager:
    def __init__(self, client_keys_dir: Path, server_public_key_path: Path,
                 server_private_key_path: Path = None, server_private_key_passphrase: str = None):
        self.client_keys_dir = client_keys_dir
        self.server_pub, _ = PGPKey.from_file(str(server_public_key_path))

        self.server_priv = None
        if server_private_key_path and Path(server_private_key_path).exists():
            self.server_priv, _ = PGPKey.from_file(str(server_private_key_path))
            if server_private_key_passphrase:
                self.server_priv.unlock(server_private_key_passphrase)

    # ========== 客户端 → 服务端 ==========
    def encrypt_for_server(self, plaintext: dict) -> str:
        """客户端用服务器公钥加密消息"""
        msg = PGPMessage.new(json.dumps(plaintext))
        enc = self.server_pub.encrypt(msg)
        return base64.b64encode(str(enc).encode()).decode()

    def decrypt_for_server(self, payload: str) -> dict:
        """服务端用服务器私钥解密消息"""
        if self.server_priv is None:
            raise ValueError("Server private key not loaded!")
        armored = base64.b64decode(payload).decode()
        pgp_msg = PGPMessage.from_blob(armored)
        return json.loads(self.server_priv.decrypt(pgp_msg).message)

    # ========== 服务端 → 客户端 ==========
    def encrypt_for_client(self, identity: str, plaintext: dict) -> str:
        """服务端用客户端公钥加密消息"""
        client_pub_path = self.client_keys_dir / f"{identity}.asc"
        if not client_pub_path.exists():
            raise FileNotFoundError(f"Missing client key: {client_pub_path}")
        client_pub, _ = PGPKey.from_file(str(client_pub_path))
        msg = PGPMessage.new(json.dumps(plaintext))
        enc = client_pub.encrypt(msg)
        return base64.b64encode(str(enc).encode()).decode()
