from flask import Flask, request, jsonify, redirect, url_for, session
from flask_cors import CORS
import sqlite3, hashlib, secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "changeme_to_a_secret_key"
CORS(app)

ADMIN_USERNAME = "admin"
ADMIN_HASHED_PASSWORD = '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92'  # 123456


def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


def init_db():
    conn = sqlite3.connect('keys.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            original_key TEXT,
            hwid TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            usage_count INTEGER DEFAULT 0,
            max_usage INTEGER DEFAULT -1
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT,
            hwid TEXT,
            private_ip TEXT,
            public_ip TEXT,
            pc_name TEXT,
            last_access TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            status TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()


@app.route('/')
def home():
    return '<h3>Máy chủ đang chạy. Truy cập <a href="/admin">Quản lý key</a>.</h3>'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        if data.get("username") == ADMIN_USERNAME and \
           hashlib.sha256(data.get("password", "").encode()).hexdigest() == ADMIN_HASHED_PASSWORD:
            session['logged_in'] = True
            return redirect('/admin')
        return "<h4 style='color:red'>Sai tài khoản hoặc mật khẩu</h4>", 401
    return '''
    <form method="POST" style="max-width:300px;margin:100px auto">
      <h3>Đăng nhập quản trị</h3>
      <input name="username" class="form-control" placeholder="Tên đăng nhập"><br>
      <input name="password" type="password" class="form-control" placeholder="Mật khẩu"><br>
      <button class="btn btn-primary w-100">Đăng nhập</button>
    </form>
    '''


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get("logged_in"): return redirect('/login')

    conn = sqlite3.connect('keys.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        action = request.form.get("action")
        key_hash = request.form.get("key_hash")
        if action == "create":
            hours = int(request.form.get("hours", 24))
            max_usage = int(request.form.get("max_usage", -1))
            new_key = secrets.token_urlsafe(32)
            khash = hash_key(new_key)
            now = datetime.now()
            expires = now + timedelta(hours=hours)
            cursor.execute(
                'INSERT INTO keys (key_hash, original_key, expires_at, max_usage) VALUES (?, ?, ?, ?)',
                (khash, new_key, expires, max_usage)
            )
            conn.commit()
            conn.close()
            session['msg'] = f'''
            <div class="alert alert-success">
                <b>Key mới:</b> {new_key}<br>
                Thời gian hiệu lực: {now.strftime('%d/%m/%Y %H:%M')} → {expires.strftime('%d/%m/%Y %H:%M')}<br>
                Số lượt sử dụng: {max_usage if max_usage != -1 else 'Không giới hạn'}
            </div>
            '''
            return redirect(url_for('admin'))

        elif action == "delete":
            cursor.execute('DELETE FROM keys WHERE key_hash = ?', (key_hash,))
            conn.commit()
            conn.close()
            session['msg'] = '<div class="alert alert-warning">Đã xóa key</div>'
            return redirect(url_for('admin'))

        elif action == "reset_hwid":
            cursor.execute('UPDATE keys SET hwid = NULL WHERE key_hash = ?', (key_hash,))
            conn.commit()
            conn.close()
            session['msg'] = '<div class="alert alert-info">Đã reset HWID</div>'
            return redirect(url_for('admin'))

    msg = session.pop('msg', '')

    cursor.execute(
        'SELECT key_hash, original_key, hwid, created_at, expires_at, is_active, usage_count, max_usage FROM keys ORDER BY created_at DESC'
    )
    keys = cursor.fetchall()
    now = datetime.now()

    def hours_left(expires):
        delta = datetime.fromisoformat(expires) - now
        return round(delta.total_seconds() / 3600, 1) if delta.total_seconds() > 0 else "Hết hạn"

    html_keys = ''.join(f"""
        <tr>
          <td>{k[0]}</td><td>{k[1]}</td><td>{k[2] or ''}</td><td>{k[3][:16]}</td><td>{k[4][:16]}</td>
          <td>{hours_left(k[4])} giờ</td>
          <td>{k[6]}</td><td>{k[7]}</td>
          <td>{"Còn hạn" if k[5] and hours_left(k[4]) != "Hết hạn" else "Hết hạn"}</td>
          <td>
            <form method='POST'><input type='hidden' name='action' value='delete'>
            <input type='hidden' name='key_hash' value='{k[0]}'><button class='btn btn-sm btn-danger'>Xóa</button></form>
          </td>
          <td>
            <form method='POST'><input type='hidden' name='action' value='reset_hwid'>
            <input type='hidden' name='key_hash' value='{k[0]}'><button class='btn btn-sm btn-warning'>Reset</button></form>
          </td>
        </tr>
    """ for k in keys)

    cursor.execute('''
        SELECT s.hwid, s.private_ip, s.public_ip, s.pc_name, s.last_access, s.ip_address, s.key_hash, s.status, s.message
        FROM sessions s ORDER BY s.last_access DESC LIMIT 20
    ''')
    sessions = cursor.fetchall()
    conn.close()

    html_sessions = ''.join(f"""
        <tr><td>{s[0]}</td><td>{s[1]}</td><td>{s[2]}</td><td>{s[3]}</td><td>{s[4]}</td><td>{s[5]}</td><td>{s[6][:8]}...</td><td>{s[7]}</td><td>{s[8]}</td></tr>
    """ for s in sessions)

    return f'''
    <html><head><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container my-5">
      <h2>Trang quản lý hệ thống key</h2>
      <a href="/logout">Đăng xuất</a><hr>{msg}
      <form method="POST" class="row g-3 mb-4">
        <input type="hidden" name="action" value="create">
        <div class="col-md-4">
          <label class="form-label"><b>Thời gian hiệu lực (giờ):</b></label>
          <input name="hours" type="number" class="form-control" value="24" required>
        </div>
        <div class="col-md-4">
          <label class="form-label"><b>Số lượt sử dụng tối đa:</b></label>
          <input name="max_usage" type="number" class="form-control" value="10" required>
        </div>
        <div class="col-md-4 d-flex align-items-end">
          <button class="btn btn-success w-100">Tạo key mới</button>
        </div>
      </form>

      <h4>Danh sách key hiện có</h4>
      <table class="table table-bordered table-sm table-striped">
        <thead><tr>
          <th>Key hash</th><th>Key gốc</th><th>HWID</th><th>Tạo lúc</th><th>Hết hạn</th><th>Còn (giờ)</th>
          <th>Đã dùng</th><th>Tối đa</th><th>Trạng thái</th><th>Xóa</th><th>Reset HWID</th>
        </tr></thead><tbody>{html_keys}</tbody>
      </table>

      <h4>Lịch sử xác thực gần đây</h4>
      <table class="table table-bordered table-sm">
        <thead><tr><th>HWID</th><th>IP nội bộ</th><th>IP công cộng</th><th>Tên máy</th><th>Thời gian</th><th>IP Client</th><th>Key</th><th>Trạng thái</th><th>Ghi chú</th></tr></thead>
        <tbody>{html_sessions}</tbody>
      </table>
    </div></body></html>
    '''


@app.route('/verify', methods=['POST'])
def verify():
    try:
        data = request.json
        key = data.get("key", "").strip()
        hwid = data.get("hwid", "").strip()
        if not key or not hwid:
            return jsonify({"status": "error", "message": "Key và HWID là bắt buộc", "valid": False}), 400

        key_hash = hash_key(key)
        conn = sqlite3.connect('keys.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM keys WHERE key_hash = ? AND is_active = 1', (key_hash,))
        key_record = cursor.fetchone()

        def log_attempt(status, message):
            try:
                cursor.execute('''
                    INSERT INTO sessions (key_hash, hwid, private_ip, public_ip, pc_name, ip_address, status, message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    key_hash,
                    hwid,
                    data.get("private_ip", "Unknown"),
                    data.get("public_ip", "Unknown"),
                    data.get("pc_name", "Unknown"),
                    request.remote_addr,
                    status,
                    message
                ))
                conn.commit()
            except Exception as log_err:
                print("Log error:", log_err)

        if not key_record:
            log_attempt("fail", "Key không hợp lệ")
            return jsonify({"status": "error", "message": "Key không hợp lệ", "valid": False}), 401

        expires_at = datetime.fromisoformat(key_record['expires_at'])
        if datetime.now() > expires_at:
            log_attempt("fail", "Key đã hết hạn")
            return jsonify({"status": "error", "message": "Key đã hết hạn", "valid": False}), 401

        usage_count = key_record['usage_count']
        max_usage = key_record['max_usage']
        if max_usage != -1 and usage_count >= max_usage:
            log_attempt("fail", "Vượt quá số lần dùng")
            return jsonify({"status": "error", "message": "Vượt quá số lần dùng", "valid": False}), 401

        current_hwid = key_record['hwid']
        if current_hwid and current_hwid != hwid:
            log_attempt("fail", "HWID không khớp")
            return jsonify({"status": "error", "message": "HWID không khớp", "valid": False}), 401

        if not current_hwid:
            cursor.execute('UPDATE keys SET hwid = ? WHERE key_hash = ?', (hwid, key_hash))

        cursor.execute('UPDATE keys SET usage_count = usage_count + 1 WHERE key_hash = ?', (key_hash,))
        log_attempt("success", "Xác thực thành công")
        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": "Xác thực thành công",
            "valid": True,
            "usage_count": usage_count + 1,
            "max_usage": max_usage,
            "expires_at": expires_at.isoformat()
        })

    except Exception as e:
        print("ERROR in /verify:", e)
        return jsonify({
            "status": "error",
            "message": f"Lỗi hệ thống: {e}",
            "valid": False
        }), 500


if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=8080)
