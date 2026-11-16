# SQLi Tactic Guide — Guided Agent (`TACTIC-SQLI-001`, WSTG-INJT-05)

> [!NOTE]
> Tài liệu này hướng dẫn Partner AI Agent cách sử dụng [`tactics/sqli/sqli_testing.yaml`](../tactics/sqli/sqli_testing.yaml) theo mô hình **Option A — Guided Agent** để kiểm thử giả thuyết SQL Injection (OWASP `WSTG-INJT-05`).
> Tactic chỉ cung cấp phương pháp luận và giới hạn an toàn; việc sinh payload cụ thể, fingerprinting DBMS và so sánh phản hồi được ủy quyền cho capability `SQLI_DETECTION` (SQLMap Adapter).

---

## 1. Cơ sở, Phạm vi và Giới hạn (v0.1)

- **Phạm vi hỗ trợ**:
  - Dò tìm (**Detection**), xác minh (**Verification**) và nhận diện DBMS cơ bản (**DBMS Fingerprinting** ở mức định danh, không khai thác).
  - Hỗ trợ 4 nhóm kỹ thuật: `ERROR`, `BOOLEAN`, `UNION`, `TIME`.
  - Hỗ trợ 5 vị trí tham số (`InputLocation`): `QUERY`, `FORM`, `JSON_BODY`, `COOKIE`, `HEADER`.
- **Ngoài phạm vi (từ chối hoặc báo `UNSUPPORTED`)**:
  - NoSQL Injection (`NOSQLI_DETECTION`), ORM query language parser injection (`LDAP_XPATH_ORM_DETECTION`), Second-order SQLi, Out-of-Band (OOB), và Stacked Queries (`S`).
  - Các hoạt động khai thác sâu bị **cấm tuyệt đối**: `--dbs`, `--tables`, `--columns`, `--dump`, `--os-shell`, `--os-cmd`, `--file-read`, `--file-write`, `--tamper` WAF bypass.
  - Tham số ở vị trí `DOM`, `MULTIPART`, `XML_BODY` chưa được SQLi Tactic v0.1 hỗ trợ tự động.

---

## 2. Dữ liệu Agent Nhận từ M1 / M2 / Policy

| Ngữ cảnh | Nguồn | Cách Agent sử dụng |
|---|---|---|
| `target_url`, `method` | `M1.EndpointDefinition` (`origin + path`, `method`) | Xác định endpoint mục tiêu và đối chiếu `ScopeGuard`. |
| `parameter_name`, `parameter_location` | `M2.InputCandidate` (`parameter_name`, `location`) | Xác định đúng điểm tiêm cần kiểm thử, kiểm tra thuộc `supported_input_locations`. |
| `request_artifact_ref` | `M1.EvidenceArtifactRecord` (`HTTP_RAW_EXCHANGE`) | Ưu tiên truyền sang `HTTP_REQUEST` và `SQLI_DETECTION` để SQLMap Adapter dựng tệp request `-r`. |
| `auth_ref` | `M1.AssessmentConfig.auth_references` | Truyền nguyên dạng opaque ref nếu endpoint cần xác thực; không tự bịa cookie/token. |
| `hypothesis` | `M2.Hypothesis` (`confidence`, `sink_relationship`, `rationale`) | Ưu tiên thứ tự kiểm thử và hiểu bối cảnh sink; **không** dùng `confidence=HIGH` để bỏ qua kiểm chứng. |
| `expected_signals` | `M2.ValidationCapabilityRequirement.expected_signals` | Nếu có `SQL_SYNTAX_ERROR` / `BOOLEAN_RESPONSE_DIFF` → ưu tiên `ERROR, BOOLEAN, UNION`; nếu có `TIMING_DIFF` → cân nhắc `TIME` khi baseline ổn định. |
| `dbms_hint` | `M1.TargetModel.technologies` | Truyền sang `SQLI_DETECTION` làm gợi ý ban đầu nếu có. |
| `execution_policy` | `M1.ExecutionPolicy` | Giới hạn số lượng request, timeout và quyền chạy active SQLi. |

---

## 3. Ánh xạ Vị trí Tham số và Chức năng SQLMap qua Adapter

Agent chỉ truyền `parameter_name`, `parameter_location`, `request_artifact_ref`, `techniques` và `risk_profile: LOW`; **SQLMap Adapter** chịu trách nhiệm dịch sang tham số SQLMap tương ứng (Agent không tự viết cờ CLI):

| `InputLocation` | Cách Adapter truyền cho SQLMap | Mức `--level` tối thiểu ở Adapter | Chức năng bị khóa ở Adapter |
|---|---|---|---|
| `QUERY` | Truyền URL hoặc tệp `-r`, khóa tham số qua `-p <parameter_name>` | `--level=1` | Khóa `--risk=1`, `--batch`, cấm `S`/`Q` |
| `FORM` | Truyền tệp `-r` (hoặc `--data` với `application/x-www-form-urlencoded`), `-p <parameter_name>` | `--level=1` | Khóa `--risk=1`, `--batch` |
| `JSON_BODY` | Truyền tệp `-r` với header `Content-Type: application/json` và body JSON mẫu, đánh dấu `*` hoặc `-p <parameter_name>` | `--level=1` | Khóa `--risk=1`, `--batch` |
| `COOKIE` | Truyền tệp `-r` có `Cookie:` header và `-p <cookie_name>` | `--level=2` | Khóa `--risk=1`, `--batch` |
| `HEADER` | Truyền tệp `-r`: dùng `--level=3 -p <header>` với `User-Agent`/`Referer`, hoặc đánh dấu `*` tại giá trị custom header đích | `--level=3` (hoặc `*`) | Không bật `--level=5` quét tràn lan |

**Những việc SQLMap tự làm (Tactic không mô tả lại)**:
- Thăm dò heuristic ban đầu (`'`) để phân biệt tham số tĩnh/động.
- Tự nhận diện DBMS (`MySQL`, `PostgreSQL`, `SQLite`, `MSSQL`, `Oracle`, ...).
- Tự chọn chuỗi đóng ngoặc/nháy, toán tử boolean và payload `ORDER BY` / `NULL` cho `UNION`.
- Tự thống kê sai lệch độ trễ cho Time-based blind (`--time-sec` hữu hạn).

---

## 4. Hướng dẫn Quyết định từng Bước (`Option A — Guided Agent`)

| Bước | Capability khuyến nghị | Agent đánh giá gì & quyết định tiếp theo |
|---|---|---|
| **1. `preflight`** | `null` | Kiểm tra `ExecutionPolicy`, `ScopeGuard`, `parameter_location`, và `auth_ref`. Nếu vi phạm policy → `POLICY_BLOCKED`; ngoài `supported_input_locations` → `UNSUPPORTED`; thiếu dữ liệu tạo request → `INCONCLUSIVE`. |
| **2. `baseline`** | `HTTP_REQUEST` (`sample_count: 2`) | Xác nhận target phản hồi ổn định (`baseline_ready == true`, `target_stable == true`). Nếu `auth_failure_detected`, `rate_limited`, hoặc `waf_or_filter_detected` → dừng ở `INCONCLUSIVE`. Nếu lỗi mạng/timeout → `ERROR`. |
| **3. `primary_detection`** | `SQLI_DETECTION` (`ERROR, BOOLEAN, UNION`, `risk_profile: LOW`) | Gọi kiểm thử các kỹ thuật in-band và boolean. Nếu có `SQLiProof` với `verified=true` → đi thẳng `finalize`. Nếu bị gián đoạn hoặc target mất ổn định → `INCONCLUSIVE`. Nếu chưa có proof và target ổn định → xét điều kiện chạy `optional_time_detection` hoặc đi tới `finalize`. |
| **4. `optional_time_detection`** *(Tùy chọn)* | `SQLI_DETECTION` (`TIME`, `risk_profile: LOW`) | Chỉ chạy nếu chính sách cho phép, `target_stable == true`, ngân sách còn đủ, **và** có ít nhất 1 tín hiệu hợp lý (`TIMING_DIFF` trong `expected_signals`, hoặc `heuristic_signal_detected == true`, hoặc hypothesis `MEDIUM`/`HIGH`). Dù kết quả thế nào đều chuyển về `finalize`. |
| **5. `finalize`** | `null` | Rà soát `confirmation_rules` để chốt `CONFIRMED`, `NOT_CONFIRMED`, hoặc `INCONCLUSIVE`. |

---

## 5. Quy tắc Kết luận và Yêu cầu Bằng chứng Tối thiểu

| Kết luận (`Outcome`) | Điều kiện bắt buộc |
|---|---|
| **`CONFIRMED`** | Có ít nhất một kỹ thuật trong `confirmed_techniques` kèm `SQLiProof` có `verified == true`, liên kết `control_observation_refs` + `test_observation_refs` và `evidence_refs` đã redact. |
| **`NOT_CONFIRMED`** | Các kỹ thuật đã chọn hoàn tất sạch (`NOT_DETECTED`), mục tiêu ổn định, không bị WAF/auth/rate-limit cản trở và không còn tín hiệu heuristic chưa giải quyết. Phải ghi rõ phạm vi `tested_techniques`. |
| **`INCONCLUSIVE`** | Chỉ có `heuristic_signal_detected == true`, thiếu `proofs`/`evidence_refs`, target bất ổn (`target_stable=false`), hoặc bị ngắt do auth/CSRF/rate-limit/WAF/hết ngân sách. |
| **`ERROR`** | Lỗi công cụ, lỗi kết nối mạng, timeout không thể khôi phục hoặc lỗi `5xx` cản trở hoàn toàn phép thử. |
| **`UNSUPPORTED`** | InputLocation hoặc biến thể SQLi (NoSQL, OOB, DOM) ngoài phạm vi hỗ trợ của v0.1. |
| **`POLICY_BLOCKED`** | Ngoài phạm vi `authorized_scope` hoặc bị `ExecutionPolicy` từ chối kiểm thử chủ động. |

**Bằng chứng tối thiểu theo từng kỹ thuật (`SQLiProof`)**:
- **`ERROR`**: Thông báo lỗi SQL đặc trưng của DBMS xuất hiện ở test request và không xuất hiện ở control observation. Lỗi HTTP 500 chung chung không đủ xác nhận.
- **`BOOLEAN`**: Cặp điều kiện đúng/sai (`true`/`false` predicates) cho ra phản hồi khác biệt có tính quy luật và lặp lại ổn định sau khi kiểm soát phần nội dung động.
- **`UNION`**: Marker kiểm thử không nhạy cảm được phản chiếu đúng vào cấu trúc phản hồi qua truy vấn `UNION` và có đối chứng với baseline.
- **`TIME`**: Độ trễ phản hồi lặp lại nhất quán qua nhiều cặp đo control/test vượt ngưỡng biến thiên nền khi `target_stable == true`.

---

## 6. Những Giới hạn Agent Tuyệt đối Không được Vượt qua

1. Không tự gán `CONFIRMED` chỉ vì `M2.Hypothesis.confidence == HIGH` hay một boolean từ log tool.
2. Không tự sửa scope, tự nâng `risk_profile` lên `MEDIUM`/`HIGH`, hoặc yêu cầu `--dump`, `--os-shell`, `--file-read`.
3. Không lặp lại nhiều lần một kỹ thuật trên cùng tham số khi `target_stable == false` hoặc `rate_limited == true`.
4. Không đưa secret thô (`Cookie`, `Authorization`, mật khẩu) vào nội dung reasoning hay trường tóm tắt kết quả.
