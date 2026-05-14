# oracle.py
import pymysql
import logging
import os
import sqlglot
import time

# Thiết lập logging ra file để dễ theo dõi
logging.basicConfig(
    filename='/shared-tmpfs/oracle_debug.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SideEffectOracle:
    def __init__(self, host='db', user='user', password='password', database='phuzz_sensors'):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        
        self.log_path = "/shared-tmpfs/mysql_general.log"
        self.last_log_pos = 0
        
        # Thử kết nối ban đầu để kiểm tra
        try:
            conn = self.get_connection()
            conn.close()
            logging.info("SideEffectOracle initialized and DB connection successful")
        except Exception as e:
            logging.error(f"SideEffectOracle failed to connect to DB: {e}")

    def get_connection(self):
        return pymysql.connect(
            host=self.host, 
            user=self.user, 
            password=self.password, 
            database=self.database, 
            autocommit=True,
            connect_timeout=2
        )

    def check_side_effects(self, marker_id):
            # Chờ 0.3s để đảm bảo MySQL đã ghi xong log và commit transaction vào ổ cứng
            time.sleep(0.3) 
            
            # =====================================================================
            # THUẬT TOÁN 1: KIỂM TRA TRẠNG THÁI VẬT LÝ CỦA DATABASE
            # (Chỉ hoạt động nếu Web App cho phép Stacked Queries - ví dụ: chạy nhiều lệnh qua dấu ;)
            # =====================================================================
            try:
                with self.get_connection() as conn:
                    with conn.cursor() as cursor:
                        # 1. INSERT
                        cursor.execute("SELECT p_id FROM __phuzz_sensor_insert WHERE p_marker = %s LIMIT 1", (marker_id,))
                        if cursor.fetchone():
                            msg = f"[*] VULN DETECTED: Algorithm 1 (DB INSERT) - Marker: {marker_id}"
                            print(msg, flush=True)
                            logging.info(msg)
                            return "Algorithm_1_DB_INSERT"

                        # 2. UPDATE 
                        cursor.execute("SELECT id FROM __phuzz_sensor_update WHERE canary_value = %s LIMIT 1", (marker_id,))
                        if cursor.fetchone():
                            msg = f"[*] VULN DETECTED: Algorithm 1 (DB UPDATE) - Marker: {marker_id}"
                            print(msg, flush=True)
                            logging.info(msg)
                            return "Algorithm_1_DB_UPDATE"
                            
                        # 3. DDL
                        table_name = f"__phuzz_tmp_{marker_id.replace('-', '_')}"
                        cursor.execute(f"SHOW TABLES LIKE '{table_name}'")
                        if cursor.fetchone():
                            msg = f"[*] VULN DETECTED: Algorithm 1 (DB DDL) - Marker: {marker_id}"
                            print(msg, flush=True)
                            logging.info(msg)
                            return "Algorithm_1_DB_DDL"
                            
            except Exception as e:
                logging.error(f"Oracle DB Check Error (Alg 1): {e}")

            # =====================================================================
            # THUẬT TOÁN 2: KIỂM TRA NHẬT KÝ MYSQL (LOG ANALYSIS)
            # (Lưới vét: Bắt mọi truy vấn, kể cả Subquery chỉ ĐỌC dữ liệu)
            # =====================================================================
            if os.path.exists(self.log_path):
                try:
                    file_size = os.path.getsize(self.log_path)
                    # Nếu file log bị xóa/reset, đưa con trỏ về 0
                    if file_size < self.last_log_pos:
                        self.last_log_pos = 0

                    with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(self.last_log_pos)
                        new_logs = f.read()
                        self.last_log_pos = f.tell()

                        # Chỉ xử lý nếu Marker xuất hiện trong phần log mới
                        if marker_id in new_logs:
                            for line in new_logs.splitlines():
                                if marker_id not in line or "Query" not in line:
                                    continue

                                # Tách lấy phần thân câu lệnh SQL
                                parts = line.split("Query", 1)
                                if len(parts) < 2: continue
                                sql_part = parts[1].strip()
                                sql_upper = sql_part.upper()
                                
                                # TỐI ƯU BỘ LỌC TỰ ĐẦU ĐỘC:
                                # Chặn CHÍNH XÁC các câu lệnh do Thuật toán 1 (ở trên) vừa gọi
                                if sql_upper.startswith("SELECT P_ID FROM __PHUZZ_SENSOR_INSERT") or \
                                sql_upper.startswith("SELECT ID FROM __PHUZZ_SENSOR_UPDATE") or \
                                sql_upper.startswith("SHOW TABLES LIKE") or \
                                sql_upper.startswith("CALL __PHUZZ_RESET"):
                                    continue

                                # Xử lý phân tích Cú pháp (AST)
                                try:
                                    expressions = sqlglot.parse(sql_part, read="mysql")
                                    for expr in expressions:
                                        if not expr: continue
                                        # Tìm tất cả các bảng được gọi trong câu lệnh
                                        tables = [table.name.lower() for table in expr.find_all(sqlglot.exp.Table)]
                                        
                                        # Nếu câu lệnh Web App có chạm vào bảng bẫy -> Đích thị là lỗ hổng!
                                        if any("phuzz_sensor" in t for t in tables):
                                            msg = f"[*] VULN DETECTED: Algorithm 2 (AST Match) - Marker: {marker_id}"
                                            print(msg, flush=True)
                                            logging.info(msg)
                                            return "Algorithm_2_AST"
                                            
                                except Exception:
                                    # FALLBACK AN TOÀN: 
                                    # Nếu Fuzzer nhét payload làm hỏng cấu trúc SQL (khiến AST lỗi), 
                                    # nhưng tên bảng bẫy và marker vẫn nằm trong lệnh -> Vẫn ghi nhận lỗi.
                                    sql_lower = sql_part.lower()
                                    if "__phuzz_sensor_insert" in sql_lower or "__phuzz_sensor_update" in sql_lower:
                                        msg = f"[*] VULN DETECTED: Algorithm 2 (Raw Match) - Marker: {marker_id}"
                                        print(msg, flush=True)
                                        logging.info(msg)
                                        return "Algorithm_2_RawLog"
                                        
                except Exception as e:
                    logging.error(f"Oracle Log Read Error (Alg 2): {e}")

            return False

    def cleanup(self):
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("CALL __phuzz_reset()")
        except Exception as e:
            logging.error(f"Oracle Cleanup Error: {e}")
