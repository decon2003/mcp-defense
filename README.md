# 🛡️ MCP Defense: Security Layer for AI Agents

`mcp-defense` là một thư viện bảo mật tiên tiến được thiết kế để bảo vệ các AI Agent sử dụng giao thức MCP (Model Context Protocol). Nó đóng vai trò như một "Tường lửa thông minh" ngăn chặn các cuộc tấn công khai thác công cụ (Tool-use abuse), rò rỉ dữ liệu và mã độc tiềm ẩn trong metadata.

---

## ✨ Tính năng chính

- **Zero-Config Protection**: Tự động nhận diện định dạng công cụ (OpenAI, Anthropic, MCP) và áp dụng các quy tắc bảo mật mặc định.
- **Attack Chain Detection**: Ngăn chặn các chuỗi hành động nguy hiểm (ví dụ: Agent đọc file nhạy cảm rồi cố tình gửi ra ngoài qua HTTP).
- **Tool Shadowing Guard**: Chống lại kỹ thuật "Shadowing" - nơi kẻ tấn công tạo ra công cụ giả mạo trùng tên để ghi đè công cụ hệ thống.
- **Dynamic Parameter Validation**: Kiểm soát tham số đầu vào trong thời gian thực (Runtime), chặn đứng Path Traversal (`../`) và Command Injection.
- **Log Security Monitoring**: Theo dõi và ghi lại mọi nỗ lực vi phạm bảo mật với hệ thống cảnh báo tích hợp.

---

## 🏗️ 5 Lớp phòng thủ cốt lõi (Core Layers)

1.  **Catalog Guard (Layer 1)**: Kiểm soát danh sách công cụ tại thời điểm nạp. Ngăn chặn giả mạo tên (Shadowing) và thay đổi Metadata bất thường.
2.  **Metadata Scanner (Layer 2)**: Quét sâu vào mô tả công cụ (Description) để phát hiện các chỉ dẫn độc hại (Prompt Injection) ẩn giấu.
3.  **LLM Auditor (Layer 3 - Optional)**: Sử dụng một mô hình ngôn ngữ độc lập để "thẩm định" ý đồ của các công cụ lạ trước khi cho phép AI Agent nhìn thấy chúng.
4.  **Parameter Guard (Layer 4)**: Lớp kiểm soát tham số runtime. Chặn đứng các hành vi đọc file trái phép hoặc truy cập tài nguyên ngoài phạm vi cho phép.
5.  **Chain Monitor (Layer 5)**: Giám sát toàn bộ quá trình hội thoại để phát hiện và chặn đứng các chuỗi tấn công phức tạp (ví dụ: Source -> Sink).

---

## 🚀 Cài đặt nhanh

```bash
pip install mcp-defense
```

---

## 🛠️ Hướng dẫn tích hợp (Quickstart)

Chỉ với vài dòng code, AI Agent của bạn sẽ được bảo vệ bởi toàn bộ 5 lớp phòng thủ:

### 1. Khởi tạo và Lọc công cụ độc hại
Nạp danh sách công cụ của bạn qua `load_tools`. Thư viện sẽ tự động loại bỏ các công cụ không an toàn.

```python
from mcp_defense import MCPDefense

# Khởi tạo với chế độ tự động chặn chuỗi tấn công
defense = MCPDefense(block_attack_chains=True)

# Bảo vệ danh sách công cụ (Hỗ trợ OpenAI, Anthropic, MCP)
# safe_tools sẽ chỉ chứa các công cụ đã vượt qua Layer 1 & 2
safe_tools = defense.load_tools(raw_tools_metadata)
```

### 2. Bảo vệ trong khi thực thi (Runtime)
Thay vì gọi trực tiếp hàm thực thi, hãy bọc nó qua `call_tool`.

```python
# Tự động kiểm tra tham số (Layer 4) và chuỗi hành vi (Layer 5)
result = defense.call_tool(
    session_id="user-session-123",
    tool_name="read_file",
    params={"path": "../../.env"}, # Sẽ bị chặn bởi Layer 4
    user_request=user_input,
    executor=my_real_tool_function # Hàm thực thi thực tế của bạn
)
```

### 3. Cấu hình quy tắc tùy chỉnh (Custom Rules)
Bạn có thể dễ dàng thêm các từ khóa hoặc giá trị bị cấm cho từng công cụ cụ thể:

```python
from mcp_defense.guard import ToolRules

defense.register_tool_rules("read_file", ToolRules(
    blocked_keywords=["../", ".env", "/etc/passwd"]
))
```

---

## 📊 Demo trực quan
Để xem cách `MCPDefense` chặn đứng các cuộc tấn công Path Traversal và Data Exfiltration trong thời gian thực, hãy chạy demo:

```bash
# Đảm bảo bạn đã cài đặt các dependency cần thiết
python blog_demo/aria_demo.py
```
Sau đó truy cập: `http://127.0.0.1:8080`

---

## 📄 License
Dự án được phát hành dưới giấy phép **MIT**. 🛡️ An toàn hơn cho kỷ nguyên AI Agent!
