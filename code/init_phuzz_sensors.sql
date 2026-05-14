CREATE DATABASE IF NOT EXISTS phuzz_sensors;
CREATE DATABASE IF NOT EXISTS phuzz_temp_db;

USE phuzz_sensors; 

CREATE TABLE IF NOT EXISTS __phuzz_sensor_insert (
    p_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    p_marker VARCHAR(64) UNIQUE NOT NULL,
    p_instance VARCHAR(32) NOT NULL,
    p_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=MEMORY;

CREATE TABLE IF NOT EXISTS __phuzz_sensor_update (
    id INT PRIMARY KEY,
    sensor_name VARCHAR(64) UNIQUE NOT NULL,
    canary_value VARCHAR(64) NOT NULL,
    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=MEMORY;

INSERT IGNORE INTO __phuzz_sensor_update (id, sensor_name, canary_value) 
VALUES (1, 'sensor_alpha', 'original_secret_123');

CREATE TABLE IF NOT EXISTS __phuzz_sensor_delete (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    marker_id VARCHAR(64) UNIQUE NOT NULL
) ENGINE=MEMORY;

INSERT IGNORE INTO __phuzz_sensor_delete (marker_id) 
VALUES ('target_1'), ('target_2'), ('target_3');

DELIMITER //
CREATE PROCEDURE IF NOT EXISTS __phuzz_reset()
BEGIN
    TRUNCATE TABLE __phuzz_sensor_insert;
    TRUNCATE TABLE __phuzz_sensor_delete;
    INSERT INTO __phuzz_sensor_delete (marker_id) VALUES ('target_1'), ('target_2'), ('target_3');
    UPDATE __phuzz_sensor_update SET canary_value = 'original_secret_123' WHERE id = 1;
END //
DELIMITER ;

GRANT ALL PRIVILEGES ON phuzz_sensors.* TO 'user'@'%';
GRANT ALL PRIVILEGES ON phuzz_temp_db.* TO 'user'@'%';
GRANT ALL PRIVILEGES ON phuzz_sensors.* TO 'root'@'%';
GRANT ALL PRIVILEGES ON phuzz_temp_db.* TO 'root'@'%';
FLUSH PRIVILEGES;