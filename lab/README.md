# Demo SQL injection → PostgreSQL log → rule / LLM local

Kiến trúc đích theo sơ đồ người dùng (gateway/HAProxy, hai nhánh web/DB, log tập
trung và map feedback) được ghi tại [ARCHITECTURE.md](ARCHITECTURE.md). Compose
hiện tại mới triển khai phần pilot một web + PG decoy, chưa có toàn bộ kiến trúc.

Nếu app đã chạy và bạn muốn bật/kiểm tra log trước, làm theo
[POSTGRES_LOG_COMMANDS.md](POSTGRES_LOG_COMMANDS.md). Lệnh nhanh cho decoy:
`python3 -m lab.logging --apply C3`, rồi `python3 -m lab.logging --tail 80`.

Bộ demo dùng chính endpoint `/login` của Vulnerable Bank. Bộ chạy gửi HTTP,
không gửi payload thẳng tới database. Dùng PostgreSQL 16 + pgAudit 16 trong một
Docker Compose project riêng tên `vulnbank-research`, volume riêng; compose gốc
của ứng dụng vẫn dùng PostgreSQL 13. Không gắn volume PostgreSQL 13 vào PostgreSQL 16.

**Trạng thái:** parser, công thức đánh giá và luồng report → rule đã có test bằng
fixture tổng hợp. Container, payload trên PostgreSQL thật và tốc độ/model LLM cần
được kiểm chứng trên Ubuntu có Docker. Chưa có số đo thực nghiệm của VPS.

## 1. Chuẩn bị Ubuntu

Máy dự kiến: 8 GB RAM, 80 GB disk, CPU, không GPU. Chọn kiến trúc x86_64 để bắt đầu;
2–4 vCPU là điểm bắt đầu đề xuất, cần đo tốc độ thực tế. Chạy từng model, không
chạy ba model đồng thời. Dung lượng model trên disk không bằng RAM khi suy luận.

Cần Docker Engine có Compose v2, Python >= 3.9, Internet để tải image/model.
Host Python chỉ dùng standard library, không cần pip install cho bộ chạy.

Từ thư mục gốc repo trên Ubuntu:

```bash
docker version
docker compose version
python3 --version
nproc
free -h
df -h /

python3 -m unittest discover -s tests -p test_lab.py -v
python3 -m lab.run --build --sessions 2 --novel-sessions 2
```

Lệnh cuối build image, khởi động lab, chạy lần lượt C0–C3, kiểm tra cấu hình thực
tế từ `pg_settings`, rồi xuất báo cáo. Không cần tự bật pgAudit bằng tay.
Lượt nhỏ có 30 request/cấu hình: 1 phiên dev × 8, 2 phiên known × 8, 2 phiên novel × 3.
Mỗi cấu hình tạo lại tiến trình web và pool, dùng cùng dữ liệu đã seed.
Payload ghi dữ liệu chỉ UPDATE một username không tồn tại để tránh đổi dữ liệu
giữa các cấu hình; đây là đánh giá **hành động thử thực hiện**, không đo tác động ghi.

Nếu cần đổi cổng, export biến trước khi chạy cả compose và Python:

```bash
export LAB_WEB_PORT=5081
export LAB_OLLAMA_PORT=11435
```

Xem web qua SSH tunnel từ máy cá nhân:

```bash
ssh -L 5080:127.0.0.1:5080 USER@VPS_IP
```

Sau đó mở `http://127.0.0.1:5080`. Bộ chạy dừng web sau khi đo xong; bật lại nếu
muốn xem giao diện:

```bash
docker compose -f lab/compose.yml start web
```

Database không publish cổng host. Web và Ollama bind `127.0.0.1`; không cần mở
firewall public cho demo. Nếu đang chạy compose gốc, nó có cách publish cổng
riêng; kiểm tra `docker ps` để phân biệt hai project.

## 2. Cấu hình C0–C3

Tất cả cùng dùng JSON log, UTC và bật sẵn extension; chỉ bật ghi audit ở C2/C3.
JSON là định dạng vận chuyển chung để tránh khác biệt parser giữa cấu hình.
`lab/run.py` chứa toàn bộ ma trận cài đặt, mỗi lượt có bản chụp `settings.json`.

| Cấu hình | Ghi SQL gốc | pgAudit | Log lỗi mặc định | Kết nối/ngắt kết nối | Bind params khi lỗi |
|---|---|---|---|---|---|
| C0 | Không | Không | Có, ERROR và SQL gây lỗi | Tắt | Tắt |
| C1 | `log_statement=all` | Không | Có | Tắt | Tắt |
| C2 | Không | `all`, tham số bật | Có | Tắt | Tắt |
| C3 | Không | `all`, tham số bật | Có | Bật | Không giới hạn |

**C2 vẫn có log lỗi PostgreSQL mặc định.** Đây không phải phép so sánh pgAudit
thuần túy sau khi loại bỏ các lỗi gốc. C3 có thể không tăng recall so với C2 trong
suite này. Chỉ kết quả chạy thật mới xác nhận được.

Bảy nhóm hành động: vượt xác thực bằng boolean, thăm dò catalog, đọc dữ liệu qua
subquery, UPDATE dạng stacked statement, lỗi cú pháp, lỗi runtime và time probe.
Có thêm login bình thường thất bại để kiểm tra false positive.

Một hành động = một request `/login` = một lần `cursor.execute`, có thể chứa nhiều
SQL statement. Chưa đo recall riêng từng statement trong stacked SQL.
Hai họ held-out của pilot là `CASE` predicate và truy vấn qua `query_to_xml`;
chúng không nằm trong few-shot examples. Đây là phép thử giữ lại họ payload trong
demo, không chứng minh model chưa từng học các kỹ thuật này trước đó.

## 3. Ground truth và RQ1

`lab/web.py` nạp app hiện có, bổ sung đo quanh `execute_query` trước khi app import.
Giữ driver psycopg2, connection pool và cách commit/rollback của hàm gốc.
Không sử dụng route SQLite `/api/login`.

Header `X-Lab-Action` và `X-Lab-Session` chỉ được ghi vào file ground truth phía
web. Không thêm marker vào SQL, `application_name` hay log PostgreSQL.
Ground truth chứa SQL, tham số, PID backend, thời gian, trạng thái driver và
SQLSTATE. Phần còn lại của ứng dụng không được instrument: phạm vi đo là `/login`.

Parser đọc JSON PostgreSQL và CSV pgAudit nằm bên trong trường `message`.
Ghép đúng SQL (chỉ bỏ whitespace ở hai đầu), PID và khoảng thực thi ±2 ms cho độ
chính xác timestamp. Nhiều dòng log của cùng hành động không làm recall vượt 1.
Không collapse whitespace bên trong literal. SQL deparse/fragment chưa ghép được
sẽ tính là bỏ sót; có thể kiểm tra `parsed.jsonl` khi cần mở rộng parser.

Mỗi lượt nằm tại `lab/results/<RUN_ID>/`:

| File | Nội dung |
|---|---|
| `environment.json` | Phiên bản PostgreSQL/pgAudit, image, cấu hình compose, máy host |
| `manifest.json` | Nhãn, họ payload, split, phiên thật, depends_on |
| `rq1.json` | Recall từng nhóm, thiếu thuộc tính, pairwise F1, chi phí và đề xuất sơ bộ |
| `rq1.csv` | Bảng config × nhóm, số hành động, recall, phần trăm bỏ sót |
| `C*/postgres.jsonl` | Log thô, đã rotate và đóng file trước khi export |
| `C*/ground_truth.jsonl` | Dữ liệu độc lập từ ứng dụng |
| `C*/parsed.jsonl` | Các sự kiện trích được từ PostgreSQL |
| `C*/http.json` | HTTP status, thời gian và kích thước response |
| `C*/dataset.json` | Dữ liệu đã đối chiếu để chấm điểm downstream |
| `C*/cost.json` | Bytes log, throughput, thời gian lượt chạy, snapshot Docker stats |

Tái dựng phiên chạy với idle timeout 1/5/15/30 phút cho hai cách: session ID DB,
và `(DB user, DB client IP, database)`. Cả hai đều không dùng ID phiên ground truth.
Báo cáo có **observed-only** và **end-to-end**; end-to-end giữ query bị mất trong
mẫu số. Qua web, IP trong DB log là IP của web container. Pool dùng chung giữa các
phiên tấn công có thể làm pairwise precision thấp dù recall query cao.

Suite ngắn không có khoảng nghỉ dài, nên các timeout có thể cho cùng kết quả.
Đó là giới hạn của bộ kịch bản, không phải kết luận timeout không có tác dụng.

Sáu thuộc tính đo: user, IP client DB, database, SQL, outcome, parameters.
Chỉ ghi lỗi mới xác nhận outcome từ parser; audit line không tự động đồng nghĩa
thành công. Suite này dùng SQL nội suy, không có bind params: tỷ lệ tham số là
`null` / không áp dụng, không phải 100%.

Chọn cấu hình nhỏ nhất hiện dựa vào log bytes và point recall >= .95 trên bảy nhóm.
Đây là gợi ý pilot, chưa khẳng định đủ ngữ cảnh RQ2 hoặc nhẹ nhất theo CPU.
Có cận dưới Wilson 95% để thấy mức bất định; đây không phải khoảng tin cậy đã
hiệu chỉnh tương quan trong phiên. Sample nhỏ thường chưa đủ để cận dưới đạt .95.
Chi phí ghi log gồm cả admin/health check, stats chỉ là snapshot, chưa phải peak.
Docker Compose stats được lấy riêng từng service. Nếu stats không khả dụng,
bộ chạy tiếp tục xuất log/chấm điểm và ghi lỗi vào `cost.json` trường
`container_stats_errors`; số liệu tài nguyên bị thiếu không được xem là bằng 0.

## 4. RQ2: rule và LLM local

Bắt đầu với rule để xác nhận pipeline không cần model:

```bash
# Thay RUN_ID bằng thư mục mà lab.run vừa in ra.
python3 -m lab.benchmark lab/results/RUN_ID/C3
```

Sáu nhãn đã thống nhất:

| Nhãn | Ý nghĩa |
|---|---|
| `normal` | Login bình thường |
| `recon` | Thăm dò catalog, lỗi runtime, thời gian |
| `auth_bypass` | Thử vượt xác thực |
| `data_read` | Thử đọc dữ liệu qua injection |
| `data_write` | Thử sửa dữ liệu qua injection |
| `unknown` | SQL hỏng hoặc chưa đủ thông tin |

Nhãn mô tả ý định thử thực hiện; thành công/thất bại là thuộc tính riêng.
`data_read`/`data_write` ưu tiên hơn `auth_bypass` nếu có cùng một query.

Bật Ollama, tải model một lần:

```bash
docker compose -f lab/compose.yml --profile llm up -d ollama
docker compose -f lab/compose.yml exec ollama ollama pull qwen3:0.6b
docker compose -f lab/compose.yml exec ollama ollama pull qwen3:1.7b
docker compose -f lab/compose.yml exec ollama ollama pull qwen3:4b
```

Chạy pilot nhỏ trước, một window và một model:

```bash
python3 -m lab.benchmark lab/results/RUN_ID/C3 \
  --models qwen3:0.6b --windows 0 --threads 2
```

Sau khi xem thời gian/RAM, chạy so sánh đủ:

```bash
python3 -m lab.benchmark lab/results/RUN_ID/C3 \
  --models qwen3:0.6b qwen3:1.7b qwen3:4b \
  --windows 0 2 4 --threads 2 --ollama http://127.0.0.1:11434
```

Nếu đổi `LAB_OLLAMA_PORT`, sửa URL `--ollama` tương ứng. Chỉ một model được nạp,
giải phóng model trước khi chuyển sang model tiếp theo. Context 4096, output tối
đa 256 tokens, temperature 0, seed 42; Qwen3 tắt thinking. RAM limit của Ollama là
5 GB. Bắt đầu với 0.6B/1.7B; 4B cần kiểm tra bộ nhớ và thời gian trên VPS thực tế.
Ba lựa chọn là so sánh kích thước trong cùng họ Qwen3; muốn so sánh kiến trúc có
thể truyền thêm model khác hỗ trợ JSON schema của Ollama sau khi tải.

Chọn model theo macro-F1 / evidence F1, tỷ lệ output lỗi, latency và tài nguyên
thực tế, không chọn sẵn model thắng khi chưa đo.

Trong `C3/benchmark/`:

- `metrics.json`, `metrics.csv`: macro-F1, F1 từng lớp, confusion matrix,
  evidence precision/recall/F1, Jaccard, thời gian, output sai định dạng và ID bịa.
- `<model>-k*.json`: từng dự đoán, output gốc, response API, lỗi và thời gian.
- `metadata.json`: prompt, few-shot, phiên bản Ollama và model digest/tags.
- `human_review.json`: mẫu ít nhất 20% mỗi lớp để người dùng kiểm tra.

Context chỉ gồm query test đã quan sát trước đó trong phiên **tái dựng** với
timeout 5 phút, không dùng phiên thật. Vì pool, context có thể bị trộn giữa các
phiên, phản ánh giới hạn của log. Truyền `--oracle-context` để đo chẩn đoán khi
biết phiên thật; kết quả vào `benchmark-oracle/`, không trộn với mặc định.

Mỗi query chỉ đưa `id`, `sql`, `outcome` vào classifier. Không đưa gold label,
gold session, split, family hay depends_on. Few-shot chỉ lấy từ phiên `dev`.
Rule hiện là baseline từ khóa đơn giản, nhận cùng window nhưng chưa tận dụng
ngữ cảnh. Output sai định dạng tính sai nhãn, không loại khỏi thống kê.
Tỷ lệ ID không tồn tại và tỷ lệ ID ngoài window được đo riêng; hai chỉ số này
không đủ để kết luận toàn bộ lời giải thích của LLM là đúng.

Gold evidence mặc định gồm query hiện tại cộng `depends_on` (suite đầu chưa có
phụ thuộc). Vì thế chưa dùng suite này để kết luận window nào tốt hơn cho tấn
công nhiều bước. Evidence F1 của rule có thể hoàn hảo vì luôn trỏ current query,
ngay cả khi nhãn sai. Cần xem cùng macro-F1 và kiểm tra tay.

Điền `reviewed_label`, `reviewed_evidence` trong file review, rồi:

```bash
python3 -m lab.benchmark lab/results/RUN_ID/C3 --review-only
```

Kết quả ở `human_review_metrics.json`. File review rỗng không được xem là đã có
ground truth con người. Chạy benchmark lại cùng thư mục sẽ ghi đè dự đoán và
metrics, nhưng giữ file review; nên lưu bản sao trước khi đổi model/window.

## 5. RQ3 và phạm vi còn cần mở rộng

`metrics.json` có điểm known/novel, từng họ novel, và delta `novel - known` với
bootstrap 95% theo phiên (500 lần, seed 42). Delta âm nghĩa là giảm chất lượng.
Để tránh so sánh tập novel thiếu lớp với known có đủ lớp, delta chỉ tính trên
giao các lớp có mặt ở cả hai split, ghi rõ trong báo cáo. Mỗi split cần >=2 phiên.
Các payload novel của pilot có độ khó chưa được kiểm định; CI có thể suy biến
vì nhiều phiên chỉ khác literal. Không diễn giải chúng thành kết luận thống kê
mạnh hoặc bằng chứng model đã khái quát trên kỹ thuật hoàn toàn mới.

RO3.3 chưa có dữ liệu phù hợp để tính tương quan: mới có hai họ held-out và độ sâu
phụ thuộc đều bằng 0. Không xuất một hệ số Spearman giả. Muốn triển khai phần
này cần thêm họ payload, kịch bản nhiều bước và đo khoảng cách cấu trúc SQL,
hàm PG, độ sâu phụ thuộc. Tương tự, muốn đánh giá đầy đủ RO2.3 cần kịch bản thật
sự cần query trước mới phân loại được và gold evidence đã kiểm tra tay.

## 6. Quan sát và dừng lab

```bash
docker compose -f lab/compose.yml ps
docker compose -f lab/compose.yml logs --tail 100 web db
docker stats --no-stream
docker compose -f lab/compose.yml --profile llm stop
```

Nếu một lượt chạy lỗi, không dùng báo cáo chưa hoàn tất. Xem logs, khắc phục rồi
chạy lượt mới; bộ chạy luôn tạo thư mục timestamp riêng. Không chạy hai bộ đo
đồng thời trên cùng project. Dữ liệu seed được giữ trong volume riêng qua các
lượt; các payload demo không thực hiện thay đổi dữ liệu lâu dài.

Tài liệu chính thức:

- PostgreSQL JSON log và giới hạn ghi statement: https://www.postgresql.org/docs/16/runtime-config-logging.html
- pgAudit, phiên bản và cấu hình: https://github.com/pgaudit/pgaudit
- Ollama generate API / structured output: https://docs.ollama.com/api/generate
- Các tag và kích thước Qwen3: https://ollama.com/library/qwen3/tags
