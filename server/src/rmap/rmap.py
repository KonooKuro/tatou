"""
rmap.py
-------
RMAP 四步握手核心逻辑
"""

import secrets


class RMAP:
    def __init__(self, identity_manager):
        self.im = identity_manager
        self.session = {}  # 存放会话状态

    # Step 1 + Step 2
    def handle_message1(self, msg1: dict) -> dict:
        try:
            # 解密客户端消息
            plaintext = self.im.decrypt_for_server(msg1["payload"])
            nonce_client = int(plaintext["nonceClient"])
            identity = plaintext["identity"]

            # 生成服务器随机数
            nonce_server = secrets.randbits(64)

            # 保存会话
            self.session[identity] = {
                "nonceClient": nonce_client,
                "nonceServer": nonce_server,
            }

            # 返回加密的 nonceServer
            response_plain = {"nonceServer": nonce_server}
            encrypted = self.im.encrypt_for_client(identity, response_plain)

            return {"payload": encrypted}

        except Exception as e:
            return {"error": f"handle_message1 failed: {e}"}

    # Step 3 + Step 4
    def handle_message2(self, msg2: dict) -> dict:
        try:
            plaintext = self.im.decrypt_for_server(msg2["payload"])
            nonce_client = int(plaintext["nonceClient"])
            nonce_server = int(plaintext["nonceServer"])

            matched_identity = None
            for ident, sess in self.session.items():
                if sess["nonceClient"] == nonce_client and sess["nonceServer"] == nonce_server:
                    matched_identity = ident
                    break

            if matched_identity is None:
                return {"error": "Session not found or nonce mismatch"}

            # 拼接生成 128-bit → 32 hex
            combined = (nonce_client << 64) | nonce_server
            result_hex = f"{combined:032x}"

            return {"result": result_hex}

        except Exception as e:
            return {"error": f"handle_message2 failed: {e}"}
