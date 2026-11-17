# Module 3 — Web Security → Partner AI Agent Handoff (Stage A & Stage B)

Tài liệu dành cho nhóm **Partner AI Agent**: những gì Web Security Team đã chuẩn hóa để Partner triển khai **MCP WSTG (Stage A — Tactic Author)** và **Test Case Planner (Stage B)** cho bộ 4 công cụ (**SQLMap**, **Dalfox**, **Playwright**, **Nuclei**) cùng primitive **`HTTP_REQUEST`**.

---

## 1. Nguồn Sự thật Duy nhất (Single Source of Truth)

Trước khi sinh hoặc chọn Tactic, hệ thống của Partner **bắt buộc đọc** các tệp chuẩn sau trong repository:

| Tệp | Vai trò |
|---|---|
| [`tactics/schemas/tactic.schema.json`](../tactics/schemas/tactic.schema.json) | JSON Schema Draft 2020-12 (`0.1.0`, `mode: "GUIDED_AGENT"`) quy định cấu trúc hợp lệ của mọi Tactic YAML. |
| [`tactics/schemas/capabilities_catalog.json`](../tactics/schemas/capabilities_catalog.json) | Danh mục máy đọc được chứa 5 Capabilities hợp lệ, `allowed_inputs`, `output_fields`, `tool_handled_automatically` và `forbidden_operations`. |
| [`docs/CAPABILITY_CONTRACTS.md`](CAPABILITY_CONTRACTS.md) | Đặc tả chi tiết I/O Contract, ngữ nghĩa `null`, cấu trúc `proofs` và 7 bất biến xác minh. |
| `tactics/**/*.yaml` | Các Tactic đã duyệt sẵn (`sqli_testing.yaml`, `xss_testing.yaml`, `cve_safe_check.yaml`). |

---

## 2. Hướng dẫn cho Stage A — MCP WSTG & Tactic Author

Stage A chỉ chạy **ở pha biên soạn/cập nhật Tactic** (hoặc khi chưa có Tactic active cho loại lỗ hổng đó), kéo tài liệu từ OWASP WSTG (ghim tag cố định, ví dụ `v4.2`) và ánh xạ sang Tactic YAML.

### 2.1. Quy tắc Ánh xạ Bắt buộc (Anti-Hallucination & Anti-Duplication)

1. **Chỉ sử dụng Capability có trong `capabilities_catalog.json`**:
   - Tuyệt đối không tự bịa tên capability ngoài danh mục (`HTTP_REQUEST`, `SQLI_DETECTION`, `XSS_DETECTION`, `BROWSER_INTERACTION`, `CVE_SAFE_CHECK`).
   - Nếu một tài liệu WSTG đòi hỏi năng lực chưa có trong catalog (ví dụ NoSQLi, OOB), đưa vào `scope.limitations` hoặc từ chối sinh bước đó.
2. **Không lặp lại `tool_handled_automatically`**:
   - Bất kỳ kỹ thuật nào đã nằm trong mảng `tool_handled_automatically` của `capabilities_catalog.json` (ví dụ SQLMap tự tìm số cột `ORDER BY`/DBMS fingerprint, Dalfox tự phân tích HTML/Attr/Script context) **không được tách thành bước riêng** trong `steps`.
3. **Chặn cứng `forbidden_operations`**:
   - Các kỹ thuật trong WSTG thuộc mảng `forbidden_operations` (ví dụ `--dump`, `--os-shell`, `--risk=2/3`, stacked queries `S`, external blind XSS callbacks, `interactsh` OOB, DoS templates) **phải đưa vào `scope.limitations` và `safety_rules`**, không được xuất hiện trong `steps` hay `suggested_inputs`.
4. **Dùng đúng tên nguồn `required_context` của M1/M2**:
   - Endpoint & Method → `M1.EndpointDefinition`
   - Parameter & Location → `M2.InputCandidate`
   - Hypothesis → `M2.Hypothesis`
   - Expected Signals → `M2.ValidationCapabilityRequirement`
   - Request Artifact → `M1.EvidenceArtifactRecord`
   - Auth & Policy → `M1.AssessmentConfig.auth_references`, `M1.ExecutionPolicy`
5. **Bắt buộc chạy Validator trước khi lưu**:
   - Mọi YAML sinh ra phải qua kiểm tra của [`tests/test_tactics/test_tactic_validation.py`](../tests/test_tactics/test_tactic_validation.py) (JSON Schema + semantic + catalog `allowed_inputs` + enum M1/M2).

---

## 3. Hướng dẫn cho Stage B — Test Case Planner (`PLAN-xxx`)

Stage B nhận `Hypothesis` (từ Module 2) + `Tactic YAML` (đã duyệt hoặc tái sử dụng) để tạo danh sách `Test Case` (`TC-001..N`).

### 3.1. Bảng Ánh xạ Lỗ hổng → Tactic → Capability → Tool

| `M2.VulnerabilityCategory` | Tactic | `recommended_capability` | Tool nền |
|---|---|---|---|
| `SQL_INJECTION` | `TACTIC-SQLI-001` (`sqli_testing.yaml`) | `HTTP_REQUEST` → `SQLI_DETECTION` | `httpx` + **SQLMap** |
| `XSS` | `TACTIC-XSS-001` (`xss_testing.yaml`) | `HTTP_REQUEST` → `XSS_DETECTION` → (`BROWSER_INTERACTION`) | `httpx` + **Dalfox** (+ **Playwright**) |
| `KNOWN_CVE` | `TACTIC-CVE-001` (`cve_safe_check.yaml`) | `HTTP_REQUEST` → `CVE_SAFE_CHECK` | `httpx` + **Nuclei** |

### 3.2. Quy tắc Sinh Phụ thuộc (`deps`) và Gom/Tách Test Case

1. **Test Case Baseline (`TC-001`)**:
   - Luôn chạy đầu tiên (`deps=[]`) với `HTTP_REQUEST` (`sample_count=2` cho SQLi/XSS, `1-2` cho CVE).
2. **Test Case Primary (`TC-002..`)**:
   - Phụ thuộc vào baseline (`deps=[TC-001]`).
   - **Khuyến nghị cho SQLi (`primary_detection`)**: Mặc định gom `techniques: ["ERROR", "BOOLEAN", "UNION"]` vào **1 Test Case** để SQLMap tái sử dụng kết quả heuristic check và DBMS fingerprint trong cùng phiên. Chỉ tách riêng khi cần theo dõi tiến độ hoặc cô lập ngân sách từng kỹ thuật.
3. **Test Case `optional: true` (Ví dụ `TC-005: TIME` hoặc `Playwright DOM verify`)**:
   - **BẮT BUỘC** đặt `deps` phụ thuộc vào các Test Case của bước `primary_detection` (ví dụ `deps=[TC-002]` hoặc `deps=[TC-002, TC-003, TC-004]`), **không** trỏ thẳng về `[TC-001]`.
   - Kèm điều kiện kích hoạt rõ ràng (`only_if_primary_unconfirmed` / `needs_browser_verification == true`), tránh trường hợp Executor chạy song song bước `optional` làm tốn ngân sách và gây nhiễu độ trễ `TIME`.
4. **Giới hạn An toàn & Ngân sách**:
   - Tổng ngân sách các Test Case không vượt quá `limits` của `ExecutionPolicy`.
   - Mọi Test Case đều mang `risk_profile: "LOW"`.

---

## 4. Ranh giới Xác minh Kết quả (Agent vs. Adapter)

- Partner Agent **không** tự gán `CONFIRMED` chỉ từ log chữ của tool hoặc `M2.Hypothesis.confidence == HIGH`.
- Chỉ các **Tool Adapter & Deterministic Verifier** của Web Security Team mới có quyền đánh dấu `proofs[].verified = true` sau khi đối chiếu control/test observations và gắn `evidence_refs` đã redact.
