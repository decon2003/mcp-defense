# 🛡️ mcp-defense

`mcp-defense` là một lớp bảo mật thông minh giúp bảo vệ AI Agent chống lại các cuộc tấn công ở tầng công cụ (MCP Tool-layer). Thư viện giúp ngăn chặn rò rỉ dữ liệu, giả mạo công cụ và các chuỗi tấn công phức tạp.

## ✨ Tính năng nổi bật
- **Zero-Config Integration**: Tự động nhận diện và phân loại rủi ro công cụ.
- **Multi-format Support**: Hỗ trợ sẵn các định dạng OpenAI, Anthropic và MCP.
- **Attack Chain Detection**: Ngăn chặn chuỗi hành động nhạy cảm (ví dụ: Đọc file -> Gửi HTTP).
- **Shadowing & Rug Pull Guard**: Chống giả mạo và thay đổi metadata công cụ trái phép.

---

## 🏗️ 5 Lớp phòng thủ cốt lõi (Core Layers)

1. **Catalog Guard**: Phát hiện các công cụ giả mạo tên (Shadowing) hoặc thay đổi nội dung sau khi đã được phê duyệt (Rug Pull).
2. **Regex Scanner**: Quét metadata công cụ để phát hiện các chỉ dẫn độc hại (Poisoning) được ẩn giấu.
3. **LLMAuditor (Opt-in)**: Sử dụng AI để kiểm duyệt ngữ nghĩa của công cụ, phát hiện các payload tinh vi.
4. **Parameter Guard**: Kiểm soát chặt chẽ các tham số đầu vào của công cụ (ví dụ: chỉ cho phép đọc file trong một thư mục nhất định).
5. **Chain Monitor**: Giám sát luồng thực thi để chặn các chuỗi tấn công "Source-to-Sink" (Rò rỉ dữ liệu từ nguồn nhạy cảm ra ngoài).

---

## 🚀 Cài đặt nhanh

```bash
pip install mcp-defense
```

---

## 🛠️ Hướng dẫn tích hợp (Quickstart)

Chỉ với 2 bước đơn giản để bảo vệ bất kỳ AI Agent nào:

### 1. Lọc công cụ khi khởi tạo
Sử dụng `load_tools` để chặn đứng các công cụ độc hại ngay từ khi nạp vào hệ thống.

```python
from mcp_defense import MCPDefense

# Khởi tạo với chế độ tự động phân loại
defense = MCPDefense(block_attack_chains=True)

# Bảo vệ danh sách công cụ (Hỗ trợ OpenAI, Anthropic, MCP)
safe_tools = defense.load_tools(raw_tools_metadata)
```

### 2. Bảo vệ khi thực thi
Bọc các cuộc gọi công cụ qua `call_tool` để kiểm soát tham số và chuỗi tấn công trong thời gian thực.

```python
result = defense.call_tool(
    session_id="user-session-123",
    tool_name=name,
    params=arguments,
    user_request=user_message,
    executor=your_actual_tool_function # Hàm thực thi thực tế của bạn
)
```

---

## 📊 Demo & Lab
Để trải nghiệm giao diện trực quan, hãy chạy bản demo có sẵn:
```bash
python blog_demo/aria_demo.py
```
Sau đó truy cập: `http://127.0.0.1:8080`

## 📄 License
MIT
