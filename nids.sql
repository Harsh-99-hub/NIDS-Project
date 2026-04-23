-- ╔══════════════════════════════════════════════════════════════════╗
-- ║         NIDS — Network Intrusion Detection System                ║
-- ║         Complete Database Setup — Compatible with server.js      ║
-- ╚══════════════════════════════════════════════════════════════════╝

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--  STEP 1: CREATE & SELECT DATABASE
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DROP DATABASE IF EXISTS NIDS_DB;
CREATE DATABASE NIDS_DB;
USE NIDS_DB;

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--  STEP 2: CREATE CORE TABLES (order matters — foreign keys)
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- 1. DEVICE
CREATE TABLE DEVICE (
    device_id   INT          PRIMARY KEY,
    device_name VARCHAR(50)  NOT NULL,
    device_ip   VARCHAR(20)  NOT NULL,
    location    VARCHAR(50),
    device_type VARCHAR(30)
);

-- 2. NETWORK_INTERFACE  (depends on DEVICE)
CREATE TABLE NETWORK_INTERFACE (
    interface_id   INT         PRIMARY KEY,
    interface_name VARCHAR(50),
    interface_type VARCHAR(30),
    mac_address    VARCHAR(20),
    device_id      INT,
    FOREIGN KEY (device_id) REFERENCES DEVICE(device_id)
);

-- 3. TRAFFIC_LOG  (depends on NETWORK_INTERFACE)
CREATE TABLE TRAFFIC_LOG (
    log_id           INT         PRIMARY KEY,
    src_ip           VARCHAR(20),
    dest_ip          VARCHAR(20),
    protocol         VARCHAR(10),
    port             INT,
    timestamp        DATETIME,
    packet_size      INT,
    session_duration INT,
    interface_id     INT,
    FOREIGN KEY (interface_id) REFERENCES NETWORK_INTERFACE(interface_id)
);

-- 4. ATTACK_SIGNATURE
CREATE TABLE ATTACK_SIGNATURE (
    signature_id INT          PRIMARY KEY,
    attack_name  VARCHAR(50)  NOT NULL,
    risk_level   VARCHAR(20),
    rule_pattern TEXT,
    description  VARCHAR(200)
);

-- 5. INTRUSION_EVENT  (depends on ATTACK_SIGNATURE)
CREATE TABLE INTRUSION_EVENT (
    event_id          INT          PRIMARY KEY,
    event_description VARCHAR(200),
    event_time        DATETIME,
    threat_level      VARCHAR(20),
    signature_id      INT,
    FOREIGN KEY (signature_id) REFERENCES ATTACK_SIGNATURE(signature_id)
);

-- 6. ALERT  (depends on INTRUSION_EVENT)
CREATE TABLE ALERT (
    alert_id      INT          PRIMARY KEY,
    alert_message VARCHAR(200) NOT NULL,
    severity      VARCHAR(20)  NOT NULL,
    alert_time    DATETIME     DEFAULT NOW(),
    alert_type    VARCHAR(50)  DEFAULT 'Security Alert',
    event_id      INT,
    FOREIGN KEY (event_id) REFERENCES INTRUSION_EVENT(event_id)
);

-- 7. ADMIN
CREATE TABLE ADMIN (
    admin_id INT         PRIMARY KEY,
    name     VARCHAR(50) NOT NULL,
    email    VARCHAR(80),
    role     VARCHAR(30)
);

-- 8. ADMIN_PHONE  (depends on ADMIN)
CREATE TABLE ADMIN_PHONE (
    admin_id INT,
    phone_no VARCHAR(15),
    PRIMARY KEY (admin_id, phone_no),
    FOREIGN KEY (admin_id) REFERENCES ADMIN(admin_id)
);

-- 9. RESPONSE_ACTION  (depends on ALERT + ADMIN)
CREATE TABLE RESPONSE_ACTION (
    action_id     INT         PRIMARY KEY,
    action_type   VARCHAR(50),
    action_status VARCHAR(20) DEFAULT 'Pending',
    action_time   DATETIME    DEFAULT NOW(),
    alert_id      INT,
    admin_id      INT,
    FOREIGN KEY (alert_id) REFERENCES ALERT(alert_id),
    FOREIGN KEY (admin_id) REFERENCES ADMIN(admin_id)
);

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--  STEP 3: SEED DATA — realistic real-time NIDS scenario
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- ── DEVICES ──────────────────────────────────────────────────────────
INSERT INTO DEVICE VALUES
(1, 'WebServer-01',  '192.168.1.10', 'Data Center A',   'Server'),
(2, 'DBServer-01',   '192.168.1.11', 'Data Center A',   'Server'),
(3, 'CoreRouter-01', '192.168.1.1',  'Network Room',    'Router'),
(4, 'Firewall-01',   '192.168.1.2',  'Network Room',    'Firewall'),
(5, 'Switch-01',     '192.168.1.3',  'Network Room',    'Switch'),
(6, 'Workstation-01','192.168.10.5', 'Office Floor 1',  'Workstation'),
(7, 'Workstation-02','192.168.10.6', 'Office Floor 2',  'Workstation'),
(8, 'BackupServer',  '192.168.1.20', 'Data Center B',   'Server');

-- ── NETWORK INTERFACES ───────────────────────────────────────────────
INSERT INTO NETWORK_INTERFACE VALUES
(101, 'eth0',   'Ethernet',  'AA:BB:CC:DD:EE:01', 1),
(102, 'eth1',   'Ethernet',  'AA:BB:CC:DD:EE:02', 2),
(103, 'eth0',   'Ethernet',  'AA:BB:CC:DD:EE:03', 3),
(104, 'eth0',   'Ethernet',  'AA:BB:CC:DD:EE:04', 4),
(105, 'eth0',   'Ethernet',  'AA:BB:CC:DD:EE:05', 5),
(106, 'wlan0',  'WiFi',      'FF:EE:DD:CC:BB:01', 6),
(107, 'wlan0',  'WiFi',      'FF:EE:DD:CC:BB:02', 7),
(108, 'eth0',   'Ethernet',  'AA:BB:CC:DD:EE:08', 8);

-- ── ATTACK SIGNATURES ────────────────────────────────────────────────
INSERT INTO ATTACK_SIGNATURE VALUES
(201, 'SQL Injection',         'High',     'SELECT.*FROM.*WHERE.*=.*OR.*1=1',          'SQL injection pattern targeting database login forms'),
(202, 'Port Scan',             'Medium',   'SYN flood across multiple ports',           'Systematic scanning of ports to find open services'),
(203, 'Brute Force Login',     'High',     'Multiple failed AUTH attempts > 10/min',    'Repeated login attempts trying to guess credentials'),
(204, 'DDoS Flood',            'Critical', 'Packet rate > 100k/sec from single source', 'Distributed Denial of Service via SYN/UDP flood'),
(205, 'Cross-Site Scripting',  'Medium',   '<script>.*alert.*</script>',                'XSS payload in HTTP request parameter'),
(206, 'Directory Traversal',   'High',     '../../../etc/passwd',                       'Attempt to access system files outside web root'),
(207, 'ARP Spoofing',          'Critical', 'Duplicate ARP reply from different MAC',    'ARP cache poisoning to intercept network traffic'),
(208, 'DNS Amplification',     'High',     'ANY DNS query > 512 bytes from spoofed IP', 'DNS amplification attack used in DDoS campaigns'),
(209, 'Ransomware Behaviour',  'Critical', 'Mass file rename + encryption pattern',     'Crypto ransomware encrypting files on shared drives'),
(210, 'Insider Data Exfil',    'High',     'Large outbound transfer > 500MB after hrs', 'Unusual large data upload detected after business hours');

-- ── INTRUSION EVENTS ─────────────────────────────────────────────────
INSERT INTO INTRUSION_EVENT VALUES
(301, 'SQL injection attempt on login API',           '2026-04-23 01:14:22', 'High',     201),
(302, 'Full port scan detected from external IP',     '2026-04-23 02:30:10', 'Medium',   202),
(303, 'Brute force on SSH port 22 — 47 attempts',    '2026-04-23 03:55:44', 'High',     203),
(304, 'DDoS flood detected — 180k packets/sec',       '2026-04-23 05:02:13', 'Critical', 204),
(305, 'XSS payload found in contact form',            '2026-04-23 07:18:59', 'Medium',   205),
(306, 'Directory traversal attempt on web server',    '2026-04-23 08:45:33', 'High',     206),
(307, 'ARP spoofing detected on LAN segment',         '2026-04-23 09:10:05', 'Critical', 207),
(308, 'DNS amplification query spike — 8x normal',   '2026-04-23 10:22:47', 'High',     208),
(309, 'Ransomware-like file activity on BackupServer','2026-04-23 11:40:18', 'Critical', 209),
(310, 'Large outbound transfer at 02:00 AM',          '2026-04-23 12:05:52', 'High',     210);

-- ── ALERTS ───────────────────────────────────────────────────────────
INSERT INTO ALERT VALUES
(401, 'SQL Injection Attack Detected on /api/login',          'High',     '2026-04-23 01:14:25', 'Security Alert', 301),
(402, 'Port Scan from 45.33.32.156 — 1024 ports in 30s',     'Medium',   '2026-04-23 02:30:15', 'Reconnaissance', 302),
(403, 'Brute Force SSH Attack — Account lockout triggered',   'High',     '2026-04-23 03:55:50', 'Security Alert', 303),
(404, 'CRITICAL: DDoS Attack — Service degradation detected', 'Critical', '2026-04-23 05:02:20', 'Availability',   304),
(405, 'XSS Payload Blocked in Web Form Submission',           'Medium',   '2026-04-23 07:19:05', 'Security Alert', 305),
(406, 'Directory Traversal Attempt — /etc/passwd Requested',  'High',     '2026-04-23 08:45:40', 'Security Alert', 306),
(407, 'CRITICAL: ARP Spoofing — MITM Attack Possible',        'Critical', '2026-04-23 09:10:10', 'Network Alert',  307),
(408, 'DNS Amplification Attack — Resolver Abused',           'High',     '2026-04-23 10:22:55', 'Network Alert',  308),
(409, 'CRITICAL: Ransomware Activity on BackupServer',        'Critical', '2026-04-23 11:40:25', 'Malware Alert',  309),
(410, 'Suspected Data Exfiltration — 2.3 GB Upload Detected', 'High',     '2026-04-23 12:06:00', 'Data Loss Alert',310);

-- ── ADMINS ───────────────────────────────────────────────────────────
INSERT INTO ADMIN VALUES
(501, 'Arun Kumar',    'arun@nids.com',    'Security Analyst'),
(502, 'Priya Sharma',  'priya@nids.com',   'Network Admin'),
(503, 'Rahul Verma',   'rahul@nids.com',   'SOC Engineer'),
(504, 'Sneha Pillai',  'sneha@nids.com',   'Incident Responder');

INSERT INTO ADMIN_PHONE VALUES
(501, '9876543210'),
(501, '9123456780'),
(502, '9988776655'),
(503, '9012345678'),
(504, '9090909090'),
(504, '9988001122');

-- ── RESPONSE ACTIONS ─────────────────────────────────────────────────
INSERT INTO RESPONSE_ACTION VALUES
(601, 'Block IP',         'Executed', '2026-04-23 01:20:00', 401, 501),
(602, 'Monitor Traffic',  'Executed', '2026-04-23 02:35:00', 402, 502),
(603, 'Reset Password',   'Executed', '2026-04-23 04:00:00', 403, 501),
(604, 'Block Traffic',    'Executed', '2026-04-23 05:10:00', 404, 503),
(605, 'Notify Admin',     'Executed', '2026-04-23 07:25:00', 405, 502),
(606, 'Block IP',         'Executed', '2026-04-23 08:50:00', 406, 501),
(607, 'Isolate Device',   'Executed', '2026-04-23 09:15:00', 407, 504),
(608, 'Block Traffic',    'Pending',  '2026-04-23 10:30:00', 408, 503),
(609, 'Shutdown Server',  'Pending',  '2026-04-23 11:45:00', 409, 504),
(610, 'Block IP',         'Pending',  '2026-04-23 12:10:00', 410, 501);

-- ── TRAFFIC LOGS (realistic mix of normal + suspicious) ──────────────
INSERT INTO TRAFFIC_LOG VALUES
(1001, '192.168.10.5',  '192.168.1.10', 'TCP',  80,   '2026-04-23 01:00:10', 1200,  45,  101),
(1002, '45.33.32.156',  '192.168.1.10', 'TCP',  22,   '2026-04-23 01:13:55', 64,    1,   101),
(1003, '45.33.32.156',  '192.168.1.10', 'TCP',  443,  '2026-04-23 01:14:10', 128,   1,   101),
(1004, '45.33.32.156',  '192.168.1.11', 'TCP',  3306, '2026-04-23 01:14:22', 512,   2,   102),
(1005, '192.168.10.6',  '8.8.8.8',      'UDP',  53,   '2026-04-23 02:05:00', 60,    1,   107),
(1006, '45.33.32.156',  '192.168.1.10', 'TCP',  1,    '2026-04-23 02:29:50', 64,    1,   101),
(1007, '45.33.32.156',  '192.168.1.10', 'TCP',  21,   '2026-04-23 02:30:05', 64,    1,   101),
(1008, '45.33.32.156',  '192.168.1.10', 'TCP',  8080, '2026-04-23 02:30:10', 64,    1,   101),
(1009, '10.0.0.55',     '192.168.1.10', 'TCP',  22,   '2026-04-23 03:50:00', 96,    1,   103),
(1010, '10.0.0.55',     '192.168.1.10', 'TCP',  22,   '2026-04-23 03:52:30', 96,    1,   103),
(1011, '10.0.0.55',     '192.168.1.10', 'TCP',  22,   '2026-04-23 03:55:44', 96,    1,   103),
(1012, '185.220.101.5', '192.168.1.10', 'UDP',  0,    '2026-04-23 05:01:00', 52,    0,   104),
(1013, '185.220.101.5', '192.168.1.10', 'UDP',  0,    '2026-04-23 05:01:01', 52,    0,   104),
(1014, '185.220.101.5', '192.168.1.10', 'UDP',  0,    '2026-04-23 05:01:02', 52,    0,   104),
(1015, '192.168.10.5',  '192.168.1.10', 'TCP',  80,   '2026-04-23 07:18:50', 980,   30,  101),
(1016, '192.168.10.6',  '192.168.1.10', 'TCP',  80,   '2026-04-23 08:44:00', 760,   22,  101),
(1017, '192.168.1.99',  '192.168.1.5',  'ARP',  0,    '2026-04-23 09:09:58', 42,    0,   105),
(1018, '192.168.1.10',  '104.21.44.12', 'TCP',  443,  '2026-04-23 10:00:00', 3200,  120, 101),
(1019, '192.168.1.20',  '172.16.0.5',   'TCP',  445,  '2026-04-23 11:39:00', 65535, 600, 108),
(1020, '192.168.1.11',  '77.88.55.77',  'TCP',  443,  '2026-04-23 12:04:30', 65535, 900, 102);

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--  STEP 4: NORMALIZATION DEMO TABLES (for viva — 1NF → 2NF → 3NF)
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- ── UNF (Un-Normalized Form) ─────────────────────────────────────────
CREATE TABLE ALERT_UNF (
    alert_id     INT,
    alert_message VARCHAR(100),
    severity      VARCHAR(20),
    admin_name    VARCHAR(50),
    admin_phone   VARCHAR(100),   -- multiple phones in one cell (violates 1NF)
    action_type   VARCHAR(50)
);

INSERT INTO ALERT_UNF VALUES
(401, 'SQL Injection',  'High',     'Arun Kumar',   '9876543210,9123456780', 'Block IP'),
(402, 'Port Scan',      'Medium',   'Priya Sharma', '9988776655',            'Monitor Traffic'),
(403, 'DDoS Attack',    'Critical', 'Rahul Verma',  '9012345678,9090909090', 'Shutdown Server');

-- ── 1NF — Atomic values, remove repeating groups ─────────────────────
CREATE TABLE ALERT_1NF (
    alert_id      INT,
    alert_message VARCHAR(100),
    severity      VARCHAR(20),
    admin_name    VARCHAR(50),
    action_type   VARCHAR(50)
);

CREATE TABLE ADMIN_PHONE_1NF (
    admin_name VARCHAR(50),
    phone      VARCHAR(15)
);

INSERT INTO ALERT_1NF VALUES
(401, 'SQL Injection', 'High',     'Arun Kumar',   'Block IP'),
(402, 'Port Scan',     'Medium',   'Priya Sharma', 'Monitor Traffic'),
(403, 'DDoS Attack',   'Critical', 'Rahul Verma',  'Shutdown Server');

INSERT INTO ADMIN_PHONE_1NF VALUES
('Arun Kumar',   '9876543210'),
('Arun Kumar',   '9123456780'),
('Priya Sharma', '9988776655'),
('Rahul Verma',  '9012345678'),
('Rahul Verma',  '9090909090');

-- ── 2NF — Remove partial dependencies (separate admin & action) ───────
CREATE TABLE ALERT_2NF (
    alert_id      INT PRIMARY KEY,
    alert_message VARCHAR(100),
    severity      VARCHAR(20),
    event_id      INT,
    event_description VARCHAR(100)   -- still has transitive dep → fixed in 3NF
);

CREATE TABLE ADMIN_2NF (
    admin_id INT PRIMARY KEY,
    name     VARCHAR(50)
);

CREATE TABLE ADMIN_PHONE_2NF (
    admin_id INT,
    phone    VARCHAR(15),
    PRIMARY KEY (admin_id, phone)
);

CREATE TABLE RESPONSE_ACTION_2NF (
    action_id   INT PRIMARY KEY,
    alert_id    INT,
    admin_id    INT,
    action_type VARCHAR(50)
);

INSERT INTO ALERT_2NF VALUES
(401, 'SQL Injection', 'High',     301, 'SQL Attack Detected'),
(402, 'Port Scan',     'Medium',   302, 'Port Scanning Detected'),
(403, 'DDoS Attack',   'Critical', 303, 'Distributed Denial of Service');

INSERT INTO ADMIN_2NF VALUES
(1, 'Arun Kumar'),
(2, 'Priya Sharma'),
(3, 'Rahul Verma');

INSERT INTO ADMIN_PHONE_2NF VALUES
(1, '9876543210'),
(1, '9123456780'),
(2, '9988776655'),
(3, '9012345678'),
(3, '9090909090');

INSERT INTO RESPONSE_ACTION_2NF VALUES
(1, 401, 1, 'Block IP'),
(2, 402, 2, 'Monitor Traffic'),
(3, 403, 3, 'Shutdown Server');

-- ── 3NF — Remove transitive dependencies (event in own table) ────────
CREATE TABLE INTRUSION_EVENT_3NF (
    event_id          INT PRIMARY KEY,
    event_description VARCHAR(100)
);

CREATE TABLE ALERT_3NF (
    alert_id      INT PRIMARY KEY,
    alert_message VARCHAR(100),
    severity      VARCHAR(20),
    event_id      INT,
    FOREIGN KEY (event_id) REFERENCES INTRUSION_EVENT_3NF(event_id)
);

CREATE TABLE ADMIN_3NF (
    admin_id INT PRIMARY KEY,
    name     VARCHAR(50)
);

CREATE TABLE ADMIN_PHONE_3NF (
    admin_id INT,
    phone    VARCHAR(15),
    PRIMARY KEY (admin_id, phone)
);

CREATE TABLE RESPONSE_ACTION_3NF (
    action_id   INT PRIMARY KEY,
    alert_id    INT,
    admin_id    INT,
    action_type VARCHAR(50)
);

INSERT INTO INTRUSION_EVENT_3NF VALUES
(301, 'SQL Attack Detected'),
(302, 'Port Scanning Detected'),
(303, 'Distributed Denial of Service');

INSERT INTO ALERT_3NF VALUES
(401, 'SQL Injection', 'High',     301),
(402, 'Port Scan',     'Medium',   302),
(403, 'DDoS Attack',   'Critical', 303);

INSERT INTO ADMIN_3NF VALUES
(1, 'Arun Kumar'),
(2, 'Priya Sharma'),
(3, 'Rahul Verma');

INSERT INTO ADMIN_PHONE_3NF VALUES
(1, '9876543210'),
(1, '9123456780'),
(2, '9988776655'),
(3, '9012345678'),
(3, '9090909090');

INSERT INTO RESPONSE_ACTION_3NF VALUES
(1, 401, 1, 'Block IP'),
(2, 402, 2, 'Monitor Traffic'),
(3, 403, 3, 'Shutdown Server');

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--  STEP 5: TRANSACTIONS & LOCKS DEMO (for viva)
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- Transaction 1: Insert new alert with savepoint + partial rollback
START TRANSACTION;
    INSERT INTO ALERT VALUES
    (420, 'Test Alert — Transaction Demo', 'Low', NOW(), 'Test', NULL);
    SAVEPOINT before_update;
    UPDATE ALERT SET severity = 'High' WHERE alert_id = 420;
    ROLLBACK TO before_update;   -- undo the severity change
COMMIT;                          -- only INSERT is committed

-- Transaction 2: Execute a response action atomically
START TRANSACTION;
    INSERT INTO RESPONSE_ACTION VALUES
    (620, 'Notify Admin', 'Executed', NOW(), 420, 501);
    UPDATE ALERT SET alert_type = 'Reviewed' WHERE alert_id = 420;
COMMIT;

-- Transaction 3: Full rollback demo
START TRANSACTION;
    DELETE FROM RESPONSE_ACTION WHERE action_id = 620;
    DELETE FROM ALERT WHERE alert_id = 420;
ROLLBACK;   -- nothing actually deleted

-- Row-level lock demo (SELECT ... FOR UPDATE)
START TRANSACTION;
    SELECT * FROM ALERT WHERE alert_id = 404 FOR UPDATE;
    UPDATE ALERT SET severity = 'Critical' WHERE alert_id = 404;
COMMIT;

-- Table-level lock demo
LOCK TABLES ALERT WRITE;
    UPDATE ALERT SET alert_type = 'Reviewed' WHERE alert_id = 402;
UNLOCK TABLES;

-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
--  STEP 6: VERIFY — run these to confirm everything loaded correctly
-- ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SELECT 'DEVICES'          AS table_name, COUNT(*) AS rows FROM DEVICE
UNION ALL
SELECT 'NETWORK_INTERFACE',              COUNT(*)         FROM NETWORK_INTERFACE
UNION ALL
SELECT 'TRAFFIC_LOG',                    COUNT(*)         FROM TRAFFIC_LOG
UNION ALL
SELECT 'ATTACK_SIGNATURE',               COUNT(*)         FROM ATTACK_SIGNATURE
UNION ALL
SELECT 'INTRUSION_EVENT',                COUNT(*)         FROM INTRUSION_EVENT
UNION ALL
SELECT 'ALERT',                          COUNT(*)         FROM ALERT
UNION ALL
SELECT 'ADMIN',                          COUNT(*)         FROM ADMIN
UNION ALL
SELECT 'ADMIN_PHONE',                    COUNT(*)         FROM ADMIN_PHONE
UNION ALL
SELECT 'RESPONSE_ACTION',               COUNT(*)         FROM RESPONSE_ACTION;