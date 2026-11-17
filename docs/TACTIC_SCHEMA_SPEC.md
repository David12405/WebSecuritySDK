# Generic Tactic Schema Specification & Validation Requirements (v0.1 — Option A)

> [!NOTE]
> Tài liệu này đặc tả **Generic Security Testing Tactic Schema** ([`tactic.schema.json`](../tactics/schemas/tactic.schema.json)) và bộ quy tắc kiểm chứng (**Validation Requirements**) theo kiến trúc **Option A — Guided Agent**.
> - **Web Security Team**: Sở hữu Generic Tactic Schema, các tệp Tactic YAML theo OWASP WSTG, Capability I/O Contracts ([`CAPABILITY_CONTRACTS.md`](CAPABILITY_CONTRACTS.md)), Tool Adapters và bộ quy tắc xác minh bằng chứng.
> - **Partner AI Agent Team**: Sở hữu AI Agent Runtime, cơ chế đọc Tactic, sinh Test Case động và vòng lặp replanning.

---

## 1. Đặc tả Generic Tactic Schema (`tactics/schemas/tactic.schema.json`)

Schema được chuẩn hóa theo **JSON Schema Draft 2020-12** với `additionalProperties: false` tại mọi cấp đối tượng, **hoàn toàn độc lập với loại lỗ hổng và công cụ** (*vulnerability-agnostic* và *tool-agnostic*).

### 1.1. Cấu trúc Cấp cao (Top-Level Fields)

| Trường | Kiểu dữ liệu | Bắt buộc | Vai trò trong mô hình Guided Agent (Option A) |
|---|---|---|---|
| `schema_version` | `"0.1.0"` | Có | Phiên bản của đặc tả Guided Tactic Schema. |
| `tactic_id` | `^TACTIC-[A-Z0-9-]+$` | Có | Định danh duy nhất, ổn định của Tactic (ví dụ `TACTIC-SQLI-001`). |
| `name` | `^[a-z][a-z0-9_]*$` | Có | Tên máy đọc được (ví dụ `sqli_testing`). |
| `mode` | `"GUIDED_AGENT"` | Có | Chế độ vận hành hiện tại (Tactic là hướng dẫn quyết định, không phải workflow executor). |
| `scope` | `object` | Có | Gồm `vulnerability` (khớp `VulnerabilityCategory`), `supported_input_locations` (khớp `InputLocation`), và `limitations`. |
| `references` | `array[string]` | Có | Mã tham chiếu OWASP WSTG (`WSTG-INJT-05`) và tài liệu hướng dẫn/contract liên quan. |
| `required_context` | `array[object]` | Có | Khai báo các đầu vào cần có từ M1/M2/Policy (`name`, `source`, `required`, `description`). |
| `capabilities` | `array[object]` | Có | Danh sách Logical Capabilities được phép sử dụng (`id`, `contract_ref`, `role?: required\|optional`). |
| `safety_rules` | `array[string]` | Có | Tập các ràng buộc an toàn mà Agent và hệ thống không được vi phạm. |
| `steps` | `array[object]` | Có | Các bước hướng dẫn quyết định (`id`, `goal`, `recommended_capability`, `optional?`, `guidance`, `suggested_inputs?`, `next_options`). |
| `outcomes` | `array[enum]` (đủ 6 giá trị) | Có | 6 trạng thái kết thúc chuẩn: `CONFIRMED`, `NOT_CONFIRMED`, `INCONCLUSIVE`, `ERROR`, `UNSUPPORTED`, `POLICY_BLOCKED`. |
| `confirmation_rules` | `array[string]` | Có | Các quy tắc bắt buộc về đối chứng và bằng chứng để được kết luận `CONFIRMED`. |
| `upgrade_notes` | `array[string]` | Không | Ghi chú lộ trình nâng cấp từ Option A sang Option C (Hybrid). |

### 1.2. Ý nghĩa Khối `steps` trong Option A (Guided Agent)

Khác với workflow engine tất định hoàn toàn, mỗi phần tử trong `steps` của Option A cung cấp:
- `id`: Định danh bước (`^[a-z][a-z0-9_]*$`, ví dụ `preflight`, `baseline`, `primary_detection`, `optional_time_detection`, `finalize`).
- `goal`: Mục tiêu kiểm thử của bước này.
- `recommended_capability`: Tên Capability đề xuất (`HTTP_REQUEST`, `SQLI_DETECTION`, ...), hoặc `null` đối với bước đánh giá logic như `preflight` và `finalize`.
- `optional`: Đánh dấu bước tùy chọn (ví dụ `optional_time_detection`). Agent có thể bỏ qua khi không thỏa điều kiện hoặc hết ngân sách.
- `guidance`: Hướng dẫn suy luận cho Agent (khi nào chạy, điều kiện thu hẹp phạm vi, lưu ý bẫy dương tính giả).
- `suggested_inputs`: Tham số gợi ý an toàn mặc định (ví dụ `risk_profile: "LOW"`, `techniques: ["ERROR", "BOOLEAN", "UNION"]`).
- `next_options`: Mảng các gợi ý chuyển tiếp `{when, action, reason}`, trong đó `action` trỏ tới một `step.id` khác hoặc một trạng thái kết thúc trong `outcomes`.

---

## 2. Kiểm chứng Khả năng Tổng quát hóa với Reflected XSS (`WSTG-INPV-01`)

Bảng đối chiếu dưới đây kiểm chứng rằng `tactic.schema.json` (`0.1.0`) biểu diễn trọn vẹn cả **SQL Injection** lẫn **Reflected XSS** mà không phải thêm hay sửa đổi Schema (không tạo tệp YAML XSS trong giai đoạn hiện tại):

| Trường Schema | `TACTIC-SQLI-001` (SQL Injection) | `TACTIC-XSS-001` (Reflected XSS — Đối chiếu thiết kế) |
|---|---|---|
| `scope.vulnerability` | `"SQL_INJECTION"` | `"XSS"` |
| `scope.supported_input_locations` | `["QUERY", "FORM", "JSON_BODY", "COOKIE", "HEADER"]` | `["QUERY", "FORM", "HEADER", "DOM"]` |
| `required_context` | `target_url`, `method`, `parameter_name`, `parameter_location`, `hypothesis`, `expected_signals`, `execution_policy`, `request_artifact_ref`, `auth_ref`, `dbms_hint` | `target_url`, `method`, `parameter_name`, `parameter_location`, `hypothesis`, `expected_signals`, `execution_policy`, `request_artifact_ref`, `auth_ref`, `csp_header_hint` |
| `capabilities` | `HTTP_REQUEST`, `SQLI_DETECTION` | `HTTP_REQUEST`, `XSS_DETECTION`, `BROWSER_INTERACTION` (`role: optional`) |
| `steps` | `preflight` → `baseline` (`HTTP_REQUEST`) → `primary_detection` (`SQLI_DETECTION`) → `optional_time_detection` (`SQLI_DETECTION`, `optional: true`) → `finalize` | `preflight` → `reflection_probe` (`HTTP_REQUEST`: kiểm tra canary lành tính có phản chiếu hay không) → `context_analysis` (`XSS_DETECTION`: đánh giá ngữ cảnh HTML/Attribute/JS và cơ chế encode) → `optional_browser_verify` (`BROWSER_INTERACTION`, `optional: true`) → `finalize` |
| `confirmation_rules` | Bằng chứng `ERROR` / `BOOLEAN` / `UNION` / `TIME` đạt `verified=true` kèm control/test observations và redacted evidence. | Canary/payload không bị mã hóa (unencoded) trong ngữ cảnh thực thi hoặc xác nhận thực thi JS trong DOM, kèm redacted HTTP/DOM evidence. |

---

## 3. Lộ trình Nâng cấp từ Option A sang Option C (Hybrid)

Thiết kế hiện tại bảo đảm tính tương thích ngược khi hệ thống tiến lên **Option C — Hybrid** trong tương lai:
1. Giữ nguyên `tactic_id`, `capabilities`, **Capability I/O Contracts** và các bất biến trong `confirmation_rules`.
2. Nâng cấp hai bước `preflight` và `finalize` thành các **mandatory deterministic system gates** do runtime cưỡng chế thay vì chỉ dựa vào hướng dẫn cho Agent.
3. Mở rộng `next_options[].when` từ mô tả ngữ nghĩa đọc hiểu cho LLM sang biểu thức vị từ có định kiểu (`{fact, op, value}`) chỉ sau khi các trường output của Capability Adapter đã ổn định ngoài thực tế.

---

## 4. Yêu cầu Kiểm chứng (Validation Requirements)

Mọi tệp Tactic mới hoặc cập nhật phải vượt qua **5 tầng kiểm tra** trước khi được chấp nhận vào repository:

1. **YAML & JSON Schema Validation**:
   - Đọc bằng `yaml.safe_load()` (cấm anchor/tag thực thi mã tùy ý).
   - Validate 100% với [`tactics/schemas/tactic.schema.json`](../tactics/schemas/tactic.schema.json) theo chuẩn **JSON Schema Draft 2020-12** (`additionalProperties: false`).
2. **Semantic Validation (Tính nhất quán nội tại của Tactic)**:
   - Mọi `step.id` không trùng lặp.
   - Mọi `next_options[].action` phải bằng một `step.id` hợp lệ trong `steps` hoặc một giá trị trong `outcomes`.
   - Mọi `recommended_capability` (khi khác `null`) phải được khai báo trong `capabilities[].id`.
   - Có ít nhất 1 bước dẫn được tới trạng thái kết thúc trong `outcomes`.
3. **Domain Alignment Validation (Khớp hợp đồng M1/M2 của SDK)**:
   - `scope.vulnerability` phải thuộc enum `VulnerabilityCategory` trong [`domain/analysis_models.py`](../src/websecuritycheck/domain/analysis_models.py).
   - Mọi giá trị trong `scope.supported_input_locations` phải thuộc enum `InputLocation` trong [`domain/enums.py`](../src/websecuritycheck/domain/enums.py).
   - Các `outcomes` khớp đúng 6 trạng thái chuẩn của hệ thống.
4. **Capability Contract Consistency**:
   - Đường dẫn `contract_ref` của từng capability trong `capabilities[]` phải trỏ tới file và tiêu đề hợp đồng tồn tại thực tế trong `docs/CAPABILITY_CONTRACTS.md`.
   - Mọi khóa trong `step.suggested_inputs` phải là trường Input hợp lệ trong hợp đồng của `recommended_capability`.
5. **Evidence & Safety Consistency**:
   - `confirmation_rules` và `safety_rules` của mọi Tactic bắt buộc quy định rõ nguyên tắc **không kết luận `CONFIRMED` chỉ từ tín hiệu heuristic hoặc boolean đơn lẻ từ công cụ**, và bắt buộc gắn bằng chứng đã redact (`evidence_refs`).
