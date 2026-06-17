# ============================================================
#  安全通信模拟系统
#  算法：ECC (P-256) + ECDSA + ECDH + AES-GCM + SHA-256
#  界面：PySide6
# ============================================================

import sys
import os
import hashlib
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QLineEdit, QGroupBox,
    QSplitter, QFrame, QScrollArea, QTabWidget, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor, QPalette, QTextCursor

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
#  密码学核心逻辑
# ============================================================

def generate_ecc_keypair():
    """生成 ECC P-256 公私钥对"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def key_to_hex(key, is_private=False):
    """将密钥序列化为十六进制字符串（用于展示）"""
    if is_private:
        raw = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        raw = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    return raw.hex()


def sha256_digest(message: bytes) -> bytes:
    """计算 SHA-256 消息摘要"""
    return hashlib.sha256(message).digest()


def ecdsa_sign(private_key, message: bytes) -> bytes:
    """使用 Alice 私钥对消息摘要进行 ECDSA 签名"""
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature


def ecdsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    """使用 Alice 公钥验证签名"""
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    """AES-GCM 加密，返回 (nonce, ciphertext)"""
    nonce = os.urandom(12)          # 96-bit 随机 Nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """AES-GCM 解密"""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def ecdh_encrypt_session_key(bob_public_key, session_key: bytes):
    """
    ECIES 风格：生成临时 ECC 密钥对，
    与 Bob 公钥做 ECDH，派生包装密钥，
    用 AES-GCM 加密会话密钥。
    返回 (ephemeral_pub_bytes, wrap_nonce, wrapped_key)
    """
    ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
    ephemeral_pub  = ephemeral_priv.public_key()
    shared_secret  = ephemeral_priv.exchange(ec.ECDH(), bob_public_key)

    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session-key-wrap"
    ).derive(shared_secret)

    wrap_nonce = os.urandom(12)
    aesgcm = AESGCM(wrap_key)
    wrapped = aesgcm.encrypt(wrap_nonce, session_key, None)

    ephemeral_pub_bytes = ephemeral_pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    return ephemeral_pub_bytes, wrap_nonce, wrapped


def ecdh_decrypt_session_key(bob_private_key, ephemeral_pub_bytes: bytes,
                              wrap_nonce: bytes, wrapped_key: bytes) -> bytes:
    """Bob 用自己私钥 + 临时公钥还原会话密钥"""
    ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_pub_bytes
    )
    shared_secret = bob_private_key.exchange(ec.ECDH(), ephemeral_pub)

    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session-key-wrap"
    ).derive(shared_secret)

    aesgcm = AESGCM(wrap_key)
    return aesgcm.decrypt(wrap_nonce, wrapped_key, None)


# ============================================================
#  全局通信数据包（模拟网络传输）
# ============================================================
class TransmissionPacket:
    def __init__(self):
        self.reset()

    def reset(self):
        self.nonce          = None   # AES-GCM nonce
        self.ciphertext     = None   # 加密后的消息
        self.ephemeral_pub  = None   # ECDH 临时公钥
        self.wrap_nonce     = None   # 包装密钥 nonce
        self.wrapped_key    = None   # 加密后的会话密钥
        self.signature      = None   # ECDSA 签名
        self.digest         = None   # 消息摘要（供对比）
        self.original_msg   = None   # 原始明文（仅 Alice 知道）
        self.session_key    = None   # 会话密钥（仅 Alice 知道）


# ============================================================
#  主界面
# ============================================================
STYLE = """
QMainWindow { background: #f5f5f7; }
QWidget     { background: #f5f5f7; color: #1d1d1f; font-family: "SF Pro Text", "Helvetica Neue", "Menlo", sans-serif; }

QGroupBox {
    border: 1px solid #d2d2d7;
    border-radius: 10px;
    margin-top: 12px;
    padding: 10px 8px 8px 8px;
    font-weight: 600;
    font-size: 12px;
    color: #1d1d1f;
    background: #ffffff;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: #6e6e73; }

QPushButton {
    background: #4A90D9;
    color: #ffffff;
    border: none;
    border-radius: 7px;
    padding: 8px 18px;
    font-size: 12px;
    font-weight: 500;
}
QPushButton:hover   { background: #357ABD; }
QPushButton:pressed { background: #2A6099; }
QPushButton:disabled { background: #d2d2d7; color: #aeaeb2; }

QPushButton#btn_alice  { background: #4A90D9; }
QPushButton#btn_alice:hover  { background: #357ABD; }

QPushButton#btn_bob    { background: #4A90D9; }
QPushButton#btn_bob:hover    { background: #357ABD; }

QPushButton#btn_danger { background: #4A90D9; }
QPushButton#btn_danger:hover { background: #357ABD; }

QPushButton#btn_reset  { background: #4A90D9; }
QPushButton#btn_reset:hover  { background: #357ABD; }

QTextEdit, QLineEdit {
    background: #ffffff;
    color: #1d1d1f;
    border: 1px solid #d2d2d7;
    border-radius: 7px;
    padding: 6px;
    font-size: 11px;
    selection-background-color: #4A90D9;
    selection-color: #ffffff;
}
QTextEdit:focus, QLineEdit:focus { border-color: #4A90D9; }

QLabel { color: #6e6e73; font-size: 11px; }
QLabel#title { color: #1d1d1f; font-size: 20px; font-weight: 700; }
QLabel#subtitle { color: #aeaeb2; font-size: 11px; }

QSplitter::handle { background: #d2d2d7; width: 1px; }

QScrollBar:vertical { background: transparent; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: #c7c7cc; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #aeaeb2; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("安全通信模拟系统")
        self.resize(1280, 820)
        self.setStyleSheet(STYLE)

        # 状态
        self.alice_priv = None
        self.alice_pub  = None
        self.bob_priv   = None
        self.bob_pub    = None
        self.packet     = TransmissionPacket()

        self._build_ui()

    # ----------------------------------------------------------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(8)
        root.setContentsMargins(12, 12, 12, 12)

        # 顶部标题
        title_bar = QHBoxLayout()
        lbl_title = QLabel("🔐  安全通信模拟系统")
        lbl_title.setObjectName("title")
        btn_reset = QPushButton("重置系统")
        btn_reset.setObjectName("btn_reset")
        btn_reset.setFixedWidth(100)
        btn_reset.clicked.connect(self._reset)
        title_bar.addWidget(lbl_title)
        title_bar.addStretch()
        title_bar.addWidget(btn_reset)
        root.addLayout(title_bar)

        # 主分割区
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(2)

        # 左：Alice 面板
        splitter.addWidget(self._build_alice_panel())
        # 中：传输数据包
        splitter.addWidget(self._build_packet_panel())
        # 右：Bob 面板
        splitter.addWidget(self._build_bob_panel())

        splitter.setSizes([400, 360, 400])
        root.addWidget(splitter, stretch=1)

        # 底部日志
        root.addWidget(self._build_log_panel())

    # ------ Alice 面板 ----------------------------------------
    def _build_alice_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(6)

        # 密钥生成
        grp_key = QGroupBox("① 密钥生成")
        g = QVBoxLayout(grp_key)

        self.btn_gen_keys = QPushButton("生成 Alice & Bob 密钥对")
        self.btn_gen_keys.setObjectName("btn_alice")
        self.btn_gen_keys.clicked.connect(self._gen_keys)

        self.txt_alice_keys = QTextEdit()
        self.txt_alice_keys.setReadOnly(True)
        self.txt_alice_keys.setFixedHeight(90)
        self.txt_alice_keys.setPlaceholderText("Alice 密钥将显示在此处…")

        g.addWidget(self.btn_gen_keys)
        g.addWidget(QLabel("Alice 密钥信息："))
        g.addWidget(self.txt_alice_keys)
        lay.addWidget(grp_key)

        # 消息输入
        grp_msg = QGroupBox("② 消息输入")
        g2 = QVBoxLayout(grp_msg)
        self.txt_input = QTextEdit()
        self.txt_input.setPlaceholderText("在此输入 Alice 要发送给 Bob 的明文消息…")
        self.txt_input.setFixedHeight(70)
        g2.addWidget(self.txt_input)
        lay.addWidget(grp_msg)

        # 加密 & 签名
        grp_enc = QGroupBox("③ 加密 + 签名（Alice 发送前处理）")
        g3 = QVBoxLayout(grp_enc)

        self.btn_encrypt = QPushButton("执行：生成密钥 → AES加密 → 保护密钥 → 计算摘要 → 签名")
        self.btn_encrypt.setObjectName("btn_alice")
        self.btn_encrypt.setEnabled(False)
        self.btn_encrypt.clicked.connect(self._alice_encrypt_and_sign)

        self.txt_alice_result = QTextEdit()
        self.txt_alice_result.setReadOnly(True)
        self.txt_alice_result.setPlaceholderText("加密和签名结果将显示在此处…")

        g3.addWidget(self.btn_encrypt)
        g3.addWidget(self.txt_alice_result)
        lay.addWidget(grp_enc, stretch=1)

        return w

    # ------ 传输数据包面板 ------------------------------------
    def _build_packet_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(6)

        grp = QGroupBox("📦 网络传输数据包（模拟）")
        g = QVBoxLayout(grp)

        self.txt_packet = QTextEdit()
        self.txt_packet.setReadOnly(True)
        self.txt_packet.setPlaceholderText("数据包内容将在 Alice 完成发送后显示…")

        # 篡改模拟
        btn_tamper = QPushButton("⚠ 模拟篡改：随机修改密文")
        btn_tamper.setObjectName("btn_danger")
        btn_tamper.clicked.connect(self._tamper)

        g.addWidget(self.txt_packet, stretch=1)
        g.addWidget(btn_tamper)
        lay.addWidget(grp, stretch=1)

        return w

    # ------ Bob 面板 ------------------------------------------
    def _build_bob_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(6)

        grp_key = QGroupBox("Bob 密钥信息")
        g = QVBoxLayout(grp_key)
        self.txt_bob_keys = QTextEdit()
        self.txt_bob_keys.setReadOnly(True)
        self.txt_bob_keys.setFixedHeight(90)
        self.txt_bob_keys.setPlaceholderText("Bob 密钥将在生成后显示…")
        g.addWidget(self.txt_bob_keys)
        lay.addWidget(grp_key)

        grp_dec = QGroupBox("④ 解密 + 验签（Bob 接收后处理）")
        g2 = QVBoxLayout(grp_dec)

        self.btn_decrypt = QPushButton("执行：解密密钥 → 解密消息 → 验证签名")
        self.btn_decrypt.setObjectName("btn_bob")
        self.btn_decrypt.setEnabled(False)
        self.btn_decrypt.clicked.connect(self._bob_decrypt_and_verify)

        self.txt_bob_result = QTextEdit()
        self.txt_bob_result.setReadOnly(True)
        self.txt_bob_result.setPlaceholderText("解密和验签结果将显示在此处…")

        g2.addWidget(self.btn_decrypt)
        g2.addWidget(self.txt_bob_result)
        lay.addWidget(grp_dec, stretch=1)

        # 测试区
        grp_test = QGroupBox("⑤ 额外测试")
        g3 = QVBoxLayout(grp_test)
        btn_wrong_pub = QPushButton("错误公钥验签测试")
        btn_wrong_pub.setObjectName("btn_danger")
        btn_wrong_pub.clicked.connect(self._test_wrong_pubkey)
        btn_wrong_priv = QPushButton("错误私钥解密测试")
        btn_wrong_priv.setObjectName("btn_danger")
        btn_wrong_priv.clicked.connect(self._test_wrong_privkey)
        g3.addWidget(btn_wrong_pub)
        g3.addWidget(btn_wrong_priv)
        lay.addWidget(grp_test)

        return w

    # ------ 日志面板 ------------------------------------------
    def _build_log_panel(self):
        grp = QGroupBox("📋 系统日志")
        g = QVBoxLayout(grp)
        grp.setFixedHeight(150)
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        g.addWidget(self.txt_log)
        return grp

    # ==========================================================
    #  业务逻辑
    # ==========================================================

    def _log(self, msg, color="#1d1d1f"):
        self.txt_log.append(f'<span style="color:{color};">{msg}</span>')
        self.txt_log.moveCursor(QTextCursor.End)

    def _reset(self):
        self.alice_priv = self.alice_pub = None
        self.bob_priv   = self.bob_pub   = None
        self.packet.reset()
        for w in [self.txt_alice_keys, self.txt_alice_result,
                  self.txt_bob_keys, self.txt_bob_result,
                  self.txt_packet, self.txt_log, self.txt_input]:
            w.clear()
        self.btn_encrypt.setEnabled(False)
        self.btn_decrypt.setEnabled(False)
        self._log("系统已重置。", "#E65100")

    # ① 生成密钥对
    def _gen_keys(self):
        self.alice_priv, self.alice_pub = generate_ecc_keypair()
        self.bob_priv,   self.bob_pub   = generate_ecc_keypair()

        alice_priv_hex = key_to_hex(self.alice_priv, is_private=True)
        alice_pub_hex  = key_to_hex(self.alice_pub)
        bob_priv_hex   = key_to_hex(self.bob_priv,   is_private=True)
        bob_pub_hex    = key_to_hex(self.bob_pub)

        self.txt_alice_keys.setPlainText(
            f"[私钥] {alice_priv_hex[:32]}…（已保密截断）\n"
            f"[公钥] {alice_pub_hex[:64]}…"
        )
        self.txt_bob_keys.setPlainText(
            f"[私钥] {bob_priv_hex[:32]}…（已保密截断）\n"
            f"[公钥] {bob_pub_hex[:64]}…"
        )

        self._log("✓ Alice 和 Bob 的 ECC P-256 密钥对已生成。", "#2E7D32")
        self._log(f"  Alice 公钥（前64字节）: {alice_pub_hex[:64]}…", "#6e6e73")
        self._log(f"  Bob   公钥（前64字节）: {bob_pub_hex[:64]}…",   "#6e6e73")
        self.btn_encrypt.setEnabled(True)

    # ② Alice 加密 + 签名
    def _alice_encrypt_and_sign(self):
        msg_text = self.txt_input.toPlainText().strip()
        if not msg_text:
            QMessageBox.warning(self, "提示", "请先输入要发送的消息！")
            return

        message = msg_text.encode("utf-8")

        # 生成随机 AES-256 会话密钥
        session_key = os.urandom(32)
        self._log("── Alice 发送流程 ──────────────────────", "#0277BD")

        # Step A：AES-GCM 加密消息
        nonce, ciphertext = aes_gcm_encrypt(session_key, message)
        self._log(f"① AES-256-GCM 加密消息", "#2E7D32")
        self._log(f"   Nonce     : {nonce.hex()}", "#6e6e73")
        self._log(f"   密文(hex) : {ciphertext.hex()[:64]}…", "#6e6e73")

        # Step B：ECDH 保护会话密钥
        ephemeral_pub_bytes, wrap_nonce, wrapped_key = \
            ecdh_encrypt_session_key(self.bob_pub, session_key)
        self._log(f"② ECDH + AES-GCM 加密会话密钥（保护密钥）", "#2E7D32")
        self._log(f"   临时公钥  : {ephemeral_pub_bytes.hex()[:64]}…", "#6e6e73")
        self._log(f"   包装密文  : {wrapped_key.hex()[:64]}…", "#6e6e73")

        # Step C：SHA-256 摘要
        digest = sha256_digest(message)
        self._log(f"③ SHA-256 摘要 : {digest.hex()}", "#2E7D32")

        # Step D：ECDSA 签名
        signature = ecdsa_sign(self.alice_priv, message)
        self._log(f"④ ECDSA 签名   : {signature.hex()[:64]}…", "#2E7D32")

        # 存入数据包
        self.packet.nonce         = nonce
        self.packet.ciphertext    = ciphertext
        self.packet.ephemeral_pub = ephemeral_pub_bytes
        self.packet.wrap_nonce    = wrap_nonce
        self.packet.wrapped_key   = wrapped_key
        self.packet.signature     = signature
        self.packet.digest        = digest
        self.packet.original_msg  = message
        self.packet.session_key   = session_key

        # 结果显示
        self.txt_alice_result.setPlainText(
            f"原始消息     : {msg_text}\n\n"
            f"会话密钥     : {session_key.hex()}\n\n"
            f"消息密文     : {ciphertext.hex()}\n\n"
            f"AES Nonce    : {nonce.hex()}\n\n"
            f"包装后密钥   : {wrapped_key.hex()}\n\n"
            f"SHA-256 摘要 : {digest.hex()}\n\n"
            f"ECDSA 签名   : {signature.hex()}"
        )

        # 传输数据包展示
        self.txt_packet.setPlainText(
            f"=== 网络传输数据包（Bob 可见） ===\n\n"
            f"[密文消息]\n{ciphertext.hex()}\n\n"
            f"[AES Nonce]\n{nonce.hex()}\n\n"
            f"[加密会话密钥]\n{wrapped_key.hex()}\n\n"
            f"[ECDH 临时公钥]\n{ephemeral_pub_bytes.hex()}\n\n"
            f"[密钥包装 Nonce]\n{wrap_nonce.hex()}\n\n"
            f"[ECDSA 签名]\n{signature.hex()}\n\n"
            f"--- （Alice 私钥和会话密钥不在数据包中）---"
        )

        self._log("✓ Alice 完成加密和签名，数据包已准备就绪。", "#2E7D32")
        self.btn_decrypt.setEnabled(True)

    # ③ Bob 解密 + 验签
    def _bob_decrypt_and_verify(self):
        p = self.packet
        if p.ciphertext is None:
            self._log("数据包为空，请先完成 Alice 发送流程。", "#C62828")
            return

        self._log("── Bob 接收流程 ──────────────────────", "#0277BD")
        result_lines = []
        success = True

        # Step A：还原会话密钥
        try:
            recovered_key = ecdh_decrypt_session_key(
                self.bob_priv, p.ephemeral_pub, p.wrap_nonce, p.wrapped_key
            )
            self._log(f"① 解密会话密钥成功 : {recovered_key.hex()}", "#2A6099")
            result_lines.append(f"解密会话密钥 : {recovered_key.hex()}")
        except Exception as e:
            self._log(f"① 解密会话密钥失败 : {e}", "#C62828")
            result_lines.append(f"解密会话密钥 : 失败 ❌")
            success = False
            self._show_bob_result(result_lines, False)
            return

        # Step B：AES-GCM 解密消息
        try:
            decrypted = aes_gcm_decrypt(recovered_key, p.nonce, p.ciphertext)
            dec_text  = decrypted.decode("utf-8")
            self._log(f"② AES-GCM 解密消息成功 : {dec_text}", "#2A6099")
            result_lines.append(f"\n解密消息     : {dec_text}")
        except Exception as e:
            self._log(f"② AES-GCM 解密消息失败 : {e}", "#C62828")
            result_lines.append(f"\n解密消息     : 失败 ❌  （消息可能被篡改）")
            success = False
            self._show_bob_result(result_lines, False)
            return

        # Step C：验证签名
        sig_ok = ecdsa_verify(self.alice_pub, decrypted, p.signature)
        if sig_ok:
            self._log("③ ECDSA 签名验证通过 ✓", "#2E7D32")
            result_lines.append(f"\nECDSA 验签   : 通过 ✓")
        else:
            self._log("③ ECDSA 签名验证失败 ✗", "#C62828")
            result_lines.append(f"\nECDSA 验签   : 失败 ✗")
            success = False

        # Step D：重新计算摘要对比
        bob_digest = sha256_digest(decrypted)
        digest_match = (bob_digest == p.digest)
        result_lines.append(f"\nSHA-256 摘要 : {bob_digest.hex()}")
        result_lines.append(f"摘要匹配     : {'一致 ✓' if digest_match else '不一致 ✗'}")
        if not digest_match:
            success = False

        self._show_bob_result(result_lines, success)

    def _show_bob_result(self, lines, success):
        status = "✅ 通信成功！消息完整，签名验证通过。" if success \
            else "❌ 通信失败！消息被篡改或签名验证未通过。"
        self.txt_bob_result.setPlainText(
            "\n".join(lines) + f"\n\n{'='*40}\n{status}"
        )
        color = "#2E7D32" if success else "#C62828"
        self._log(f"{'='*10} {status} {'='*10}", color)

    # ④ 篡改模拟
    def _tamper(self):
        if self.packet.ciphertext is None:
            self._log("数据包为空，无法篡改。", "#C62828")
            return
        ct = bytearray(self.packet.ciphertext)
        ct[0] ^= 0xFF  # 翻转第一个字节
        self.packet.ciphertext = bytes(ct)
        self._log("⚠ 已篡改密文第一个字节（XOR 0xFF），请点击 Bob 解密验证。", "#C62828")
        self.txt_packet.setPlainText(
            self.txt_packet.toPlainText().replace(
                "=== 网络传输数据包（Bob 可见）",
                "=== ⚠ 数据包已被篡改！"
            )
        )

    # ⑤ 错误公钥测试
    def _test_wrong_pubkey(self):
        if self.packet.signature is None:
            self._log("请先完成 Alice 发送流程。", "#C62828")
            return
        wrong_priv, wrong_pub = generate_ecc_keypair()
        ok = ecdsa_verify(wrong_pub, self.packet.original_msg, self.packet.signature)
        if ok:
            self._log("错误公钥验签：异常通过（不应发生）", "#C62828")
        else:
            self._log("错误公钥验签：验签失败 ✗  ← 符合预期，签名与公钥不匹配。", "#E65100")
        self.txt_bob_result.setPlainText(
            "【错误公钥测试】\n\n"
            "使用随机生成的陌生公钥验证 Alice 的签名。\n\n"
            f"结果：验签{'通过（异常）' if ok else '失败 ✗'}\n\n"
            "说明：数字签名必须与签名者的公钥配对，\n"
            "      使用错误公钥无法通过验证，确保了身份认证。"
        )

    # ⑥ 错误私钥测试
    def _test_wrong_privkey(self):
        if self.packet.wrapped_key is None:
            self._log("请先完成 Alice 发送流程。", "#C62828")
            return
        wrong_priv, _ = generate_ecc_keypair()
        try:
            ecdh_decrypt_session_key(
                wrong_priv, self.packet.ephemeral_pub,
                self.packet.wrap_nonce, self.packet.wrapped_key
            )
            self._log("错误私钥解密：异常成功（不应发生）", "#C62828")
            result = "结果：解密成功（异常，不应发生）"
        except Exception:
            self._log("错误私钥解密：解密失败 ✗  ← 符合预期，无法恢复会话密钥。", "#E65100")
            result = "结果：解密失败 ✗\n\n说明：ECDH 密钥交换依赖 Bob 的真实私钥，\n      使用错误私钥无法派生正确的包装密钥，\n      因此无法解密会话密钥，后续消息解密也将失败。"

        self.txt_bob_result.setPlainText(
            f"【错误私钥测试】\n\n使用随机生成的陌生私钥尝试解密会话密钥。\n\n{result}"
        )


# ============================================================
#  程序入口
# ============================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
