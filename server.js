// ╔══════════════════════════════════════════════════════════╗
// ║         NIDS — Network Intrusion Detection System        ║
// ║                  Backend Server (Node.js)                ║
// ╚══════════════════════════════════════════════════════════╝

const express = require('express');
const mysql   = require('mysql2');
const cors    = require('cors');
const path    = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // serves index.html from same folder

// ── DATABASE CONNECTION ───────────────────────────────────────────
const db = mysql.createConnection({
    host:     'localhost',
    user:     'root',
    password: 'Harsh@99',
    database: 'NIDS_DB'
});

db.connect((err) => {
    if (err) {
        console.error('❌  DB Connection Failed:', err.message);
        process.exit(1);
    }
    console.log('✅  Connected to NIDS_DB');
});

// ── HELPER: query wrapper ─────────────────────────────────────────
function q(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.query(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  DASHBOARD STATS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/stats', async (req, res) => {
    try {
        const [
            [totalAlerts],
            [criticalAlerts],
            [totalDevices],
            [totalTraffic],
            [executedActions],
            [totalEvents]
        ] = await Promise.all([
            q('SELECT COUNT(*) AS c FROM ALERT'),
            q("SELECT COUNT(*) AS c FROM ALERT WHERE severity IN ('Critical','High')"),
            q('SELECT COUNT(*) AS c FROM DEVICE'),
            q('SELECT COUNT(*) AS c FROM TRAFFIC_LOG'),
            q("SELECT COUNT(*) AS c FROM RESPONSE_ACTION WHERE action_status = 'Executed'"),
            q('SELECT COUNT(*) AS c FROM INTRUSION_EVENT')
        ]);

        res.json({
            totalAlerts:     totalAlerts.c,
            criticalAlerts:  criticalAlerts.c,
            totalDevices:    totalDevices.c,
            totalTraffic:    totalTraffic.c,
            executedActions: executedActions.c,
            totalEvents:     totalEvents.c
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ALERTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/alerts', async (req, res) => {
    try {
        const rows = await q(`
            SELECT  a.alert_id,
                    a.alert_message,
                    a.severity,
                    a.alert_time,
                    a.alert_type,
                    ie.event_description,
                    ie.threat_level
            FROM    ALERT a
            LEFT JOIN INTRUSION_EVENT ie ON a.event_id = ie.event_id
            ORDER BY a.alert_time DESC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/alerts', async (req, res) => {
    const { alert_id, alert_message, severity, alert_type, event_id } = req.body;
    if (!alert_id || !alert_message || !severity) {
        return res.status(400).json({ error: 'alert_id, alert_message, severity are required' });
    }
    try {
        await q(
            'INSERT INTO ALERT (alert_id, alert_message, severity, alert_time, alert_type, event_id) VALUES (?, ?, ?, NOW(), ?, ?)',
            [alert_id, alert_message, severity, alert_type || 'Security Alert', event_id || null]
        );
        res.json({ success: true, message: 'Alert created' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/alerts/:id', async (req, res) => {
    try {
        // Remove dependent response actions first
        await q('DELETE FROM RESPONSE_ACTION WHERE alert_id = ?', [req.params.id]);
        await q('DELETE FROM ALERT WHERE alert_id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  DEVICES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/devices', async (req, res) => {
    try {
        const rows = await q('SELECT * FROM DEVICE ORDER BY device_id');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/devices', async (req, res) => {
    const { device_id, device_name, device_ip, location, device_type } = req.body;
    if (!device_id || !device_name || !device_ip) {
        return res.status(400).json({ error: 'device_id, device_name, device_ip are required' });
    }
    try {
        await q(
            'INSERT INTO DEVICE VALUES (?, ?, ?, ?, ?)',
            [device_id, device_name, device_ip, location || '', device_type || '']
        );
        res.json({ success: true, message: 'Device added' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/devices/:id', async (req, res) => {
    try {
        await q('DELETE FROM DEVICE WHERE device_id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  TRAFFIC LOGS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/traffic', async (req, res) => {
    try {
        const rows = await q(`
            SELECT  tl.*,
                    ni.interface_name,
                    d.device_name,
                    d.location
            FROM    TRAFFIC_LOG tl
            LEFT JOIN NETWORK_INTERFACE ni ON tl.interface_id = ni.interface_id
            LEFT JOIN DEVICE d             ON ni.device_id    = d.device_id
            ORDER BY tl.timestamp DESC
            LIMIT 200
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  INTRUSION EVENTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/events', async (req, res) => {
    try {
        const rows = await q(`
            SELECT  ie.*,
                    ats.attack_name,
                    ats.risk_level,
                    ats.description AS sig_description
            FROM    INTRUSION_EVENT ie
            LEFT JOIN ATTACK_SIGNATURE ats ON ie.signature_id = ats.signature_id
            ORDER BY ie.event_time DESC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ATTACK SIGNATURES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/signatures', async (req, res) => {
    try {
        const rows = await q('SELECT * FROM ATTACK_SIGNATURE ORDER BY signature_id');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ADMINS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/admins', async (req, res) => {
    try {
        const rows = await q(`
            SELECT  a.*,
                    GROUP_CONCAT(ap.phone_no SEPARATOR ', ') AS phones
            FROM    ADMIN a
            LEFT JOIN ADMIN_PHONE ap ON a.admin_id = ap.admin_id
            GROUP BY a.admin_id
            ORDER BY a.admin_id
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  RESPONSE ACTIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/actions', async (req, res) => {
    try {
        const rows = await q(`
            SELECT  ra.*,
                    al.alert_message,
                    al.severity,
                    adm.name AS admin_name,
                    adm.role AS admin_role
            FROM    RESPONSE_ACTION ra
            LEFT JOIN ALERT al  ON ra.alert_id = al.alert_id
            LEFT JOIN ADMIN adm ON ra.admin_id = adm.admin_id
            ORDER BY ra.action_time DESC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/actions', async (req, res) => {
    const { action_id, action_type, action_status, alert_id, admin_id } = req.body;
    if (!action_id || !action_type || !alert_id || !admin_id) {
        return res.status(400).json({ error: 'action_id, action_type, alert_id, admin_id required' });
    }
    try {
        await q(
            'INSERT INTO RESPONSE_ACTION (action_id, action_type, action_status, action_time, alert_id, admin_id) VALUES (?, ?, ?, NOW(), ?, ?)',
            [action_id, action_type, action_status || 'Pending', alert_id, admin_id]
        );
        res.json({ success: true, message: 'Action created' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/actions/:id', async (req, res) => {
    const { action_status } = req.body;
    try {
        await q(
            'UPDATE RESPONSE_ACTION SET action_status = ? WHERE action_id = ?',
            [action_status, req.params.id]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SERVE FRONTEND
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  START
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.listen(3000, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════╗');
    console.log('║   🛡  NIDS Server → http://localhost:3000  ║');
    console.log('╚══════════════════════════════════════════╝');
    console.log('');
});