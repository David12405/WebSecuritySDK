# Capability I/O Contracts (v0.1 — Specification)

> [!NOTE]
> Tài liệu này đặc tả hợp đồng Đầu vào/Đầu ra (I/O Contracts) cho các **Logical Capabilities** dùng trong Module 3 theo mô hình **Option A — Guided Agent**.
> Tactic chỉ sử dụng tên trường logic ổn định; **Tool Adapter** của Web Security Team chịu trách nhiệm chuyển đổi sang cờ công cụ thực tế, dựng tệp HTTP request, redact dữ liệu nhạy cảm và xác minh `proofs`.

---

## 1. Quy ước Chung cho Mọi Capability I/O

1. **`execution_status` (Bắt buộc)**: `COMPLETED | FAILED | TIMEOUT | CANCELLED`. Tách biệt rạch ròi giữa lỗi vận hành/hạ tầng công cụ (`FAILED`/`TIMEOUT`) và kết quả bảo mật (`NOT_DETECTED`).
2. **`artifact_refs` (Bắt buộc)**: Danh sách các mã tham chiếu bằng chứng (`EVD-xxx` / opaque logical refs). Trả về `[]` nếu không có. Mọi dữ liệu thô gắn với `artifact_refs` phải được `redaction` (ẩn `Authorization`, `Cookie`, token, password) trước khi lưu trữ.
3. **Ngữ nghĩa của `null` (Three-Valued Logic)**: `null` biểu thị *"chưa đo được / chưa đủ mẫu"* (ví dụ `target_stable: null` khi chỉ gửi 1 request). Tuyệt đối **không** đồng nghĩa `false`.
4. **Fail-Closed khi Output sai lệch**: Nếu Adapter trả về output thiếu trường bắt buộc hoặc vi phạm các bất biến ở Mục 4, lớp xác minh/tổng hợp buộc phải gán `INCONCLUSIVE` hoặc `ERROR` theo nguyên nhân; không bao giờ mặc định `CONFIRMED`.
5. **Tách biệt với `probe_http` của Module 1**: Capability `HTTP_REQUEST` của Module 3 dùng để đánh giá baseline/stability; Adapter bọc ngoài hoặc gọi lại `probe_http` ([`probes.py`](../mcp_servers/websec_tools/probes.py)) mà không làm vỡ schema `HTTPProbeResult` hiện có của Module 1.

---

## 2. `HTTP_REQUEST`

Kiểm tra khả năng kết nối trực tiếp tới đích, xác nhận hiệu lực phiên xác thực, phát hiện sớm rate-limit/WAF, và thu thập bằng chứng đối chứng nền (`baseline_artifact_refs`) kèm đánh giá độ ổn định.

### Input (`HTTP_REQUEST`)

| Trường | Kiểu | Bắt buộc | Ý nghĩa & Ràng buộc |
|---|---|---|---|
| `request_artifact_ref` | `opaque_ref \| null` | Không | Tham chiếu tới HTTP request mẫu từ Module 1 (`HTTP_RAW_EXCHANGE`); ưu tiên dùng khi có. |
| `target_url` | `string` | Có | URL tuyệt đối đã được `ScopeGuard` kiểm tra thuộc `authorized_scope`. |
| `method` | `string` | Có | HTTP method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`). |
| `headers_ref` | `opaque_ref \| null` | Không | Tham chiếu bộ headers không lộ secret trong prompt Agent. |
| `body_ref` | `opaque_ref \| null` | Không | Tham chiếu mẫu body template (form/JSON). |
| `auth_ref` | `opaque_ref \| null` | Không | Tham chiếu ngữ cảnh xác thực (`VAULT-...`), giải mã nội bộ bên trong Adapter. |
| `sample_count` | `integer` | Không (Mặc định `2`) | Số lượng request mẫu lành tính (`1..3`) để đánh giá `target_stable`. |
| `timeout_seconds` | `integer` | Có | Giới hạn thời gian cho mỗi request. |

*Lưu ý tái tạo request:* Khi `request_artifact_ref` không chứa raw HTTP request đầy đủ (do Module 1 đã redact), Adapter được phép dựng lại request từ `(target_url, method, headers_ref, body_ref)` kết hợp giải mã `auth_ref` ngay trong ranh giới thực thi cô lập.

### Output (`HTTP_REQUEST`)

| Trường | Kiểu | Bắt buộc | Ý nghĩa |
|---|---|---|---|
| `execution_status` | `enum` | Có | `COMPLETED \| FAILED \| TIMEOUT \| CANCELLED`. |
| `http_status` | `integer \| null` | Có | Mã trạng thái HTTP thực nhận (`100..599`), hoặc `null` nếu lỗi kết nối. |
| `reachable` | `boolean \| null` | Có | `true` nếu nhận được phản hồi HTTP từ đích. |
| `auth_failure_detected` | `boolean \| null` | Có | `true` khi xác nhận lỗi phiên/auth (`401`, redirect về `/login`, hoặc `403` kèm thông báo auth). Không suy diễn mù quáng mọi `403` đều là hết phiên. |
| `rate_limited` | `boolean \| null` | Có | `true` nếu gặp HTTP `429` hoặc dấu hiệu throttling (`Retry-After`). |
| `waf_or_filter_detected` | `boolean \| null` | Có | `true` nếu phản hồi chứa dấu hiệu chặn từ WAF/IPS. |
| `target_stable` | `boolean \| null` | Có | `true` nếu các mẫu lặp lại ổn định về status, cấu trúc nội dung và độ trễ; `null` nếu `sample_count < 2`. |
| `baseline_ready` | `boolean` | Có | `true` chỉ khi request tái hiện ổn định, không bị chặn và sẵn sàng làm mốc đối chứng (không suy ra chỉ từ một lần HTTP `200`). |
| `artifact_refs` | `array[opaque_ref]` | Có | Tham chiếu tới bản ghi `HTTP_RAW_EXCHANGE` đã redact. |
| `error_code` | `string \| null` | Có | Mã lỗi chuẩn (`E_TIMEOUT`, `E_CONNECT`, `E_SCOPE`, ...) khi `execution_status != COMPLETED`. |

---

## 3. `SQLI_DETECTION`

Thực hiện dò tìm và xác minh lỗ hổng SQL Injection cùng DBMS fingerprinting phục vụ nhận diện trên các tham số quan hệ được cấp phép, ủy quyền sinh payload và chạy kỹ thuật kiểm thử cho công cụ nền (SQLMap) trong giới hạn an toàn nghiêm ngặt.

### Input (`SQLI_DETECTION`)

| Trường | Kiểu | Bắt buộc | Ý nghĩa & Ràng buộc |
|---|---|---|---|
| `request_artifact_ref` | `opaque_ref \| null` | Không | Tham chiếu request mẫu từ M1/baseline để Adapter dựng tệp `-r` cho SQLMap. |
| `target_url` | `string` | Có | URL đích đã kiểm tra scope. |
| `method` | `string` | Có | HTTP method. |
| `parameter_name` | `string` | Có | Tên tham số mục tiêu (`M2.InputCandidate.parameter_name`). |
| `parameter_location` | `enum` | Có | `QUERY \| FORM \| JSON_BODY \| COOKIE \| HEADER`. |
| `auth_ref` | `opaque_ref \| null` | Không | Tham chiếu xác thực, giải mã nội bộ khi tạo request `-r`. |
| `baseline_artifact_refs` | `array[opaque_ref]` | Có | Ít nhất 1 artifact reference từ bước `baseline` dùng làm đối chứng. |
| `techniques` | `array[enum]` | Có | Tập con khác rỗng của `["ERROR", "BOOLEAN", "UNION", "TIME"]`. Cấm `S` (stacked) và `Q` (inline) ở v0.1. |
| `dbms_hint` | `string \| null` | Không | Gợi ý DBMS từ `TargetModel.technologies` (chỉ làm hint, không khóa cứng nếu chưa kiểm chứng). |
| `max_requests` | `integer` | Có | Ngân sách HTTP requests tối đa cho lần thực thi. |
| `timeout_seconds` | `integer` | Có | Giới hạn thời gian tối đa của lần thực thi. |
| `risk_profile` | `enum` | Có | Bắt buộc `LOW` trong v0.1 (Adapter ép `--risk=1`, `--batch`, cấm `--dump`, `--dbs`, `--os-shell`). |

### Output (`SQLI_DETECTION`)

| Trường | Kiểu | Bắt buộc | Ý nghĩa |
|---|---|---|---|
| `execution_status` | `enum` | Có | `COMPLETED \| FAILED \| TIMEOUT \| CANCELLED`. |
| `detection_status` | `enum` | Có | `CONFIRMED \| NOT_DETECTED \| HEURISTIC_ONLY \| INCONCLUSIVE`. |
| `tested_techniques` | `array[enum]` | Có | Danh sách kỹ thuật thực tế đã chạy hoàn tất. |
| `confirmed_techniques` | `array[enum]` | Có | Các kỹ thuật có phần tử proof đạt `verified=true`. |
| `heuristic_signal_detected` | `boolean` | Có | `true` nếu xuất hiện dấu hiệu lỗi/biến động sơ bộ nhưng chưa đủ xác minh. |
| `target_stable` | `boolean \| null` | Có | Độ ổn định phản hồi trong lúc chạy detection. |
| `auth_failure_detected` | `boolean \| null` | Có | Lỗi phiên/CSRF xảy ra trong lúc kiểm thử. |
| `rate_limited` | `boolean \| null` | Có | Bị giới hạn tốc độ giữa chừng. |
| `waf_or_filter_detected` | `boolean \| null` | Có | WAF/filter can thiệp làm sai lệch phép thử. |
| `dbms_identified` | `string \| null` | Có | DBMS nhận diện được (ví dụ `SQLite`, `MySQL`, `PostgreSQL`) ở mức không phá hoại. |
| `proofs` | `array[SQLiProof]` | Có | Bằng chứng có cấu trúc theo từng kỹ thuật. |
| `artifact_refs` | `array[opaque_ref]` | Có | Tham chiếu tới log SQLMap và các HTTP exchanges đã redact. |
| `error_code` | `string \| null` | Có | Mã lỗi kỹ thuật khi không hoàn tất. |

### Cấu trúc Phần tử `SQLiProof` (trong `proofs`)

| Trường | Kiểu | Bắt buộc | Ý nghĩa |
|---|---|---|---|
| `technique` | `enum` | Có | `ERROR \| BOOLEAN \| UNION \| TIME`. |
| `parameter_name` | `string` | Có | Tham số thực sự được chứng minh có lỗ hổng. |
| `verification_method` | `string` | Có | Ví dụ: `error_signature_match`, `boolean_differential_pairs`, `union_marker_reflection`, `timing_delay_contrast`. |
| `control_observation_refs` | `array[opaque_ref]` | Có | Quan sát đối chứng (control/baseline). |
| `test_observation_refs` | `array[opaque_ref]` | Có | Quan sát khi chèn payload kiểm thử. |
| `evidence_refs` | `array[opaque_ref]` | Có | Bằng chứng đã redact (bắt buộc khác rỗng khi `verified=true`). |
| `redacted_payload_summary` | `string \| null` | Không | Tóm tắt payload chứng minh đã ẩn bí mật; không xuất secret hay dữ liệu dump. |
| `repeatable` | `boolean \| null` | Có | Phép thử có lặp lại ổn định qua nhiều lần đối chứng hay không. |
| `verified` | `boolean` | Có | **Chỉ do lớp Adapter / Result Verifier tất định gán `true` khi đạt đủ bằng chứng; LLM tuyệt đối không tự đặt.** |

---

## 4. Invariants (Bất biến Bắt buộc)

1. **`CONFIRMED` phải có chứng minh đa tầng**: `detection_status == "CONFIRMED"` chỉ hợp lệ khi `execution_status == "COMPLETED"`, `confirmed_techniques` không rỗng, và mỗi kỹ thuật trong `confirmed_techniques` đều có `SQLiProof` tương ứng với `verified == true`, `evidence_refs` khác rỗng, và có đủ `control_observation_refs` + `test_observation_refs`.
2. **Cấm suy diễn từ Heuristic**: `HEURISTIC_ONLY` hoặc `heuristic_signal_detected == true` không bao giờ tự động sinh ra `CONFIRMED`; nếu không thể xác minh kỹ thuật cụ thể, kết quả cuối cùng phải là `INCONCLUSIVE`.
3. **Giới hạn phạm vi của `NOT_DETECTED`**: `NOT_DETECTED` chỉ hợp lệ khi tất cả `tested_techniques` chạy sạch mà không có tín hiệu chưa giải quyết; kết quả tương ứng là `NOT_CONFIRMED` trong phạm vi kỹ thuật đã thử, **không** khẳng định mục tiêu miễn nhiễm SQLi.
4. **Tính toàn vẹn của phép đối chứng**: Nếu `target_stable == false`, `rate_limited == true`, hoặc `auth_failure_detected == true` làm sai lệch đối chứng → kết luận bắt buộc là `INCONCLUSIVE`.
5. **Điều kiện riêng cho `TIME`**: Bằng chứng `TIME` chỉ được chấp nhận `verified == true` khi `target_stable == true`, `repeatable == true` và độ trễ vượt biến thiên nền qua nhiều cặp đo control/test.
6. **Quan hệ với Domain Models của SDK**: Mọi `artifact_refs` phát sinh ở Module 3 đều lưu qua `EvidenceArtifactRecord` (`HTTP_RAW_EXCHANGE`, `TOOL_RAW_OUTPUT`) gắn với `ToolExecutionResult` trong hợp đồng hiện tại của [`domain/models.py`](../src/websecuritycheck/domain/models.py).
