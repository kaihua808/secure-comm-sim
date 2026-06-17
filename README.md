# 安全通信模拟系统

一个基于 ECC 的端到端加密通信模拟器，通过可视化界面演示 Alice → Bob 的完整加密流程。

## 功能

- **密钥生成**：为 Alice 和 Bob 各自生成 ECC P-256 公私钥对
- **加密发送**：AES-256-GCM 加密消息，ECDH 保护会话密钥，ECDSA 签名
- **解密验证**：Bob 还原会话密钥、解密消息、验证签名和摘要
- **攻击模拟**：中间人篡改密文、错误公钥验签、错误私钥解密

## 算法

| 算法 | 用途 |
|------|------|
| ECC P-256 | 公私钥对生成 |
| ECDH | 会话密钥交换（ECIES 模式） |
| HKDF | 从共享密钥派生包装密钥 |
| AES-256-GCM | 消息对称加密 / 会话密钥封装 |
| ECDSA | 消息数字签名与验证 |
| SHA-256 | 消息完整性摘要 |

## 项目结构

```
├── main.py              # 启动入口
├── crypto/
│   └── core.py          # 加密函数 + TransmissionPacket
├── ui/
│   ├── styles.py        # 样式表
│   └── main_window.py   # 主窗口 UI 与业务逻辑
└── secure_comm_gui.py   # 原始单文件版本
```

## 环境要求

- Python 3.10+
- PySide6
- cryptography

## 安装与运行

```bash
# 克隆项目
git clone https://github.com/kaihua808/secure-comm-sim.git
cd secure-comm-sim

# 创建虚拟环境并安装依赖
python3 -m venv venv
source venv/bin/activate
pip install PySide6 cryptography

# 启动
python main.py
```

## 使用流程

1. 点击 **生成 Alice & Bob 密钥对** 初始化双方密钥
2. 在消息框输入明文，点击 **执行加密 + 签名**
3. 中间面板查看网络传输数据包内容
4. 点击 **执行解密 + 验签** 查看 Bob 的接收结果
5. 可选：点击 **模拟篡改** 后再解密，观察完整性校验失败的效果
