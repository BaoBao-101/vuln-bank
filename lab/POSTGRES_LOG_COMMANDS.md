# Cấu hình và kiểm tra log trên Ubuntu

Chạy từ thư mục gốc `vuln-bank` trên server. File này tiếp nối
[HAPROXY_GATEWAY_COMMANDS.md](HAPROXY_GATEWAY_COMMANDS.md); không cài lại HAProxy.

Có hai project, đều có service tên `db`. Luôn giữ đúng `-f`:

| Thành phần | Compose | Log |
|---|---|---|
| DB của app chính | `docker-compose.yml` | PostgreSQL 13 native, chưa có pgAudit |
| DB decoy để đo RQ1 | `lab/compose.yml` | PostgreSQL 16 JSON + pgAudit, C0–C3 |
| Gateway trên host | systemd `haproxy` | journal, theo hướng dẫn gateway |
| App decoy | `lab/compose.yml`, service `web` | stdout/stderr; ground truth khi chạy kịch bản |

Trạng thái kiểm thử: helper đã có kiểm thử tự động bằng mock. Các lệnh bên dưới
cần chạy trên server để xác nhận PostgreSQL/HAProxy thực tế; chưa được chạy từ
workspace này lên server của bạn. Không chạy `lab.run` cùng lúc với các thao tác
đổi cấu hình thủ công trong hướng dẫn này.

## 1. Kiểm tra và khởi động decoy nếu cần

```bash
pwd
docker compose -f docker-compose.yml ps
docker compose -f lab/compose.yml ps
```

Nếu chưa có `db` và `web` của decoy, chạy:

```bash
LAB_WEB_PORT=5080 docker compose -f lab/compose.yml up -d --build db web
curl --noproxy '*' --fail --show-error --retry 30 --retry-all-errors --retry-delay 2 --max-time 10 http://127.0.0.1:5080/healthz
```

Lệnh `up` không chạy init SQL lần nữa trên volume đã có dữ liệu. Helper bên dưới
sẽ đảm bảo extension tồn tại trước khi bật audit. Không cần xóa volume hoặc đổi
phiên bản DB chính để bật log trên decoy.

## 2. Bật C3 trước để kiểm tra log

Đồng bộ các file mới của thư mục `lab/` từ workspace lên server trước khi chạy.

```bash
python3 -m lab.logging --apply C3
curl --noproxy '*' --fail --show-error --retry 30 --retry-all-errors --retry-delay 2 --max-time 10 http://127.0.0.1:5080/healthz
```

Helper chỉ nhắm project decoy. Nó kiểm tra PostgreSQL 16, preload pgAudit,
collector, JSON và UTC trước khi đổi cấu hình. Đổi profile sẽ stop/start web
decoy một lúc để mở lại connection pool; không restart database hoặc web chính.

Output cần có `matching_profiles: ["C3"]`, `pgaudit_version` khác null và đường
dẫn `current_json_log`. Mỗi setting có `value`, `source`, `pending_restart` để
kiểm tra nguồn cấu hình và tình trạng chờ restart.

Các giá trị C3 chính:

```text
logging_collector                  on
log_destination                    jsonlog
shared_preload_libraries            pgaudit
log_timezone                       UTC
log_statement                      none
log_min_messages                   warning
log_min_error_statement            error
log_connections                    on
log_disconnections                 on
log_parameter_max_length_on_error  -1
pgaudit.log                        all
pgaudit.log_parameter              on
pgaudit.log_catalog                on
```

`log_statement=none` ở C3 là có chủ đích: SQL được ghi qua pgAudit, tránh nhân đôi
mọi query bằng native statement log. Native ERROR vẫn ghi SQL gây lỗi.

Để chỉ xem trạng thái mà không đổi cấu hình:

```bash
python3 -m lab.logging
```

`logging_collector`, preload, đích log và UTC đã được đặt qua command của DB trong
`lab/compose.yml`. Các setting trong C0–C3 được lưu bằng `ALTER SYSTEM`, tồn tại
qua restart của cùng volume. Nếu sửa command của DB, cần áp dụng lại bằng
`docker compose -f lab/compose.yml up -d db web`; riêng restart không đọc lại
Compose đã sửa. Một thay đổi startup có thể ngắt kết nối DB hiện có.

## 3. Tạo ba loại query và đọc log

Dùng `psql` để kiểm tra đường ghi log trước, chưa phải phép đo SQL injection:

```bash
docker compose -f lab/compose.yml exec -T db psql -X -v ON_ERROR_STOP=1 -U postgres -d vulnerable_bank -c "SELECT 'lab_log_ok' AS marker;"
```

Hai lệnh dưới **dự kiến báo ERROR**; chạy từng lệnh riêng để nhìn SQLSTATE/lỗi:

```bash
docker compose -f lab/compose.yml exec -T db psql -X -v ON_ERROR_STOP=1 -U postgres -d vulnerable_bank -c "SELEC 'lab_log_syntax';"
```

```bash
docker compose -f lab/compose.yml exec -T db psql -X -v ON_ERROR_STOP=1 -U postgres -d vulnerable_bank -c "SELECT 1/0 /* lab_log_runtime */;"
```

Đọc file JSON trong container:

```bash
python3 -m lab.logging --tail 80
```

Cần thấy:

- Query thành công: trường `message` bắt đầu `AUDIT:`, chứa `lab_log_ok`.
- Lỗi cú pháp: `error_severity=ERROR`, `state_code=42601`, `statement` chứa `SELEC`.
- Lỗi runtime: `state_code=22012`, `statement` chứa phép chia cho 0.
- Các dòng kết nối/ngắt kết nối khi `psql` tạo và đóng connection mới.

Lệnh `psql exec` dùng Unix socket nên có thể không có IP client trong log. Để
kiểm tra IP qua app, gửi HTTP ở bước tiếp theo. Một dòng `AUDIT:` không tự chứng
minh query hay transaction thành công; phải xem lỗi/kết quả độc lập.

JSON log được collector ghi vào `lab_logs` trong volume PostgreSQL. Vì vậy
`docker compose -f lab/compose.yml logs db` chủ yếu hữu ích cho startup; không
phải cách lấy toàn bộ log SQL khi `log_destination=jsonlog`.

## 4. Kiểm tra query đi qua web

Truy cập thẳng decoy để loại trừ lỗi routing trong bước kiểm tra log:

```bash
curl --noproxy '*' --silent --show-error --max-time 15 \
  -H 'Content-Type: application/json' \
  --data '{"username":"lab_web_log_probe","password":"wrong-demo-password"}' \
  http://127.0.0.1:5080/login

python3 -m lab.logging --tail 80
```

HTTP 401 là bình thường với tài khoản không tồn tại. Log DB cần có query chứa
`lab_web_log_probe`, user `postgres`, DB `vulnerable_bank`, backend PID/session
và `remote_host` của web container. Không mong `remote_host` là IP trình duyệt.

Nếu đi qua gateway 8080, map mặc định rỗng sẽ chuyển tới **app chính**, không
phải decoy. Muốn kiểm tra đường watch, dùng policy và `curl --interface` trong
bước 5 của hướng dẫn HAProxy. Log gateway phải có `branch=decoy` trước khi kết
luận query đó cần xuất hiện trong log PG decoy. Không thay map giữa benchmark.

## 5. Đổi C0–C3 thủ công

Chạy **một** profile tại một thời điểm:

```bash
python3 -m lab.logging --apply C0
```

```bash
python3 -m lab.logging --apply C1
```

```bash
python3 -m lab.logging --apply C2
```

```bash
python3 -m lab.logging --apply C3
```

| Profile | SQL thành công | SQL lỗi | Kết nối |
|---|---|---|---|
| C0 | Không bật ghi toàn bộ | Native ERROR | Tắt |
| C1 | Native `log_statement=all` | Native ERROR | Tắt |
| C2 | pgAudit `all` | Native ERROR vẫn bật | Tắt |
| C3 | pgAudit `all` | Native ERROR + bind params khi có | Bật |

Sau khi đổi, gửi query **mới** rồi xem log. Các dòng từ profile trước vẫn nằm
trong file; không được lấy chúng để kết luận cấu hình mới cũng ghi được.

## 6. Xuất log ra host

```bash
python3 -m lab.logging --export-dir lab/results/manual-logs
```

Helper yêu cầu rotate sang tên file mới, rồi copy file vừa đóng và snapshot
setting vào thư mục timestamp mới. Không copy một file đang được ghi rồi coi đó
là một bản export đầy đủ. Bản này là **file log trước rotation**, có thể chứa
nhiều profile hoặc query quản trị trước đó; chưa phải dataset benchmark tách lượt.
Lệnh export cũng tạo một số log quản trị trong file kế tiếp.

Thu các nguồn khác riêng vào thư mục timestamp:

```bash
capture_dir="lab/results/log-capture-$(date -u +%Y%m%dT%H%M%S%N)"
mkdir -p "$capture_dir"
sudo journalctl -u haproxy --utc --since '30 minutes ago' -o json --no-pager > "$capture_dir/gateway.journal.jsonl"
docker compose -f lab/compose.yml logs --no-color --timestamps --since 30m web > "$capture_dir/decoy-app.log" 2>&1
docker compose -f docker-compose.yml logs --no-color --timestamps --since 30m web > "$capture_dir/main-app.log" 2>&1
```

Đây là export thủ công theo nguồn, chưa phải collector chạy liên tục. App hiện
ghi debug text ra stdout; file đó chưa phải JSON telemetry HTTP→DB có request ID.
Ground truth `lab/results/ground_truth.jsonl` chỉ được tạo khi request có header
kịch bản của bộ chạy, không tự xuất hiện cho mọi lượt đăng nhập thủ công.

## 7. Nếu muốn bật log native cho DB chính đang chạy

Bước này tùy chọn, không cần làm để đo log decoy. PostgreSQL 13 không có JSON log
như decoy; không áp dụng lệnh pgAudit của decoy lên image `postgres:13` hiện tại.

Lưu setting trước khi thay đổi:

```bash
main_backup="lab/results/main-log-settings-$(date -u +%Y%m%dT%H%M%S%N).csv"
mkdir -p lab/results
docker compose -f docker-compose.yml exec -T db psql -X --csv -U postgres -d vulnerable_bank -c "SELECT name,setting,source FROM pg_settings WHERE name IN ('logging_collector','log_destination','log_statement','log_connections','log_disconnections','log_min_error_statement','log_line_prefix');" > "$main_backup"
cat "$main_backup"
```

Với Compose gốc, collector mặc định tắt và stderr đi ra Docker logs. Chỉ dùng
block sau nếu bản kiểm tra ở trên xác nhận đúng điều đó:

```bash
docker compose -f docker-compose.yml exec -T db psql -X -v ON_ERROR_STOP=1 -U postgres -d vulnerable_bank <<'SQL'
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';
ALTER SYSTEM SET log_min_error_statement = 'error';
ALTER SYSTEM SET log_line_prefix = '%m [%p] session=%c user=%u db=%d client=%r app=%a sqlstate=%e ';
SELECT pg_reload_conf();
SQL

docker compose -f docker-compose.yml logs --tail 80 db
```

Không cần restart DB chính. Reload không thay thế `log_connections` của các
connection đã mở trước đó; hãy dùng một kết nối mới để kiểm tra. Query qua app
chính sẽ chỉ xuất hiện ở log DB chính, không nằm trong file PG decoy.

## 8. Khi bắt đầu đo RQ1

```bash
python3 -m lab.run --sessions 2 --novel-sessions 2
```

Bộ chạy tự chuyển C0→C3, stop/start web decoy và export riêng từng lượt. Nó phát
request thẳng cổng decoy, chưa đi qua HAProxy. Không thay cấu hình log hay policy
trong lúc lệnh này chạy. Xem `rq1.json`/`rq1.csv` sau khi lượt chạy hoàn tất.

Compose hiện tắt rotation theo thời gian/kích thước để bộ đo giữ được một file
cho mỗi lượt. Đây là cấu hình đo ngắn hạn; rotation thủ công không xóa file cũ.
Theo dõi dung lượng, xuất và lưu trữ log định kỳ trước khi thu liên tục lâu dài.

## Tài liệu chính thức

- [PostgreSQL 16: JSON log, collector, statement/error logging](https://www.postgresql.org/docs/16/runtime-config-logging.html).
- [PostgreSQL 13: native logging](https://www.postgresql.org/docs/13/runtime-config-logging.html).
- [pgAudit REL_16_STABLE: preload, extension và cấu hình](https://github.com/pgaudit/pgaudit/blob/REL_16_STABLE/README.md).
