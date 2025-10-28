import os
import csv
import json
import re
import uuid
import time
import subprocess
import hashlib
import secrets
from time import sleep
from threading import Lock
from flask import (Flask, render_template, request, redirect, url_for,
                   session, send_file, jsonify, Response, abort)
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # change this
socketio = SocketIO(app, cors_allowed_origins="*")

@app.after_request
def add_security_headers(response):
    # Cache control
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # CSP to prevent injection attacks through proxies
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "media-src 'self' https:; "
        "frame-src 'self' https://www.youtube.com https://player.vimeo.com; "
        "connect-src 'self' wss: ws:;"
    )
    response.headers['Content-Security-Policy'] = csp
    
    return response

# ----------------- CONFIG -----------------
UPLOAD_FOLDER = 'static/uploads'
THUMB_FOLDER = os.path.join(UPLOAD_FOLDER, 'thumbs')
METADATA_FILE = 'metadata.json'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(THUMB_FOLDER, exist_ok=True)
CHAT_FILE = 'chat.json'

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB per file
MAX_FOLDER_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB total
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mov', '.webm', '.mkv', '.mp3', '.wav', '.ogg'}

# Thread locks
folder_lock = Lock()
meta_lock = Lock()

# In-memory connected users for bandwidth logic (optional)
connected_users = set()

# Rate limiting for login attempts
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIMEOUT = 300  # 5 minutes

def check_rate_limit(ip):
    now = time.time()
    if ip in login_attempts:
        attempts, first_attempt = login_attempts[ip]
        if now - first_attempt < LOGIN_TIMEOUT:
            if attempts >= MAX_LOGIN_ATTEMPTS:
                return False
            login_attempts[ip] = (attempts + 1, first_attempt)
        else:
            login_attempts[ip] = (1, now)
    else:
        login_attempts[ip] = (1, now)
    return True

def clear_rate_limit(ip):
    if ip in login_attempts:
        del login_attempts[ip]

# ----------------- Helpers -----------------
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${pwd_hash.hex()}"

def verify_password(password, stored_hash):
    try:
        salt, pwd_hash = stored_hash.split('$')
        return hash_password(password, salt) == stored_hash
    except:
        return False

def check_credentials(username, password):
    with open('users.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['username'] == username:
                # Support both hashed and legacy plain text (for migration)
                if '$' in row['password']:
                    return verify_password(password, row['password'])
                else:
                    # Legacy plain text - still works but should be migrated
                    return row['password'] == password
    return False

def load_chat():
    if not os.path.exists(CHAT_FILE):
        return []
    with open(CHAT_FILE, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except:
            return []

def save_chat(chat):
    with open(CHAT_FILE, 'w', encoding='utf-8') as f:
        json.dump(chat, f, indent=2)

def validate_csrf_token():
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    session_token = session.get('csrf_token')
    return token and session_token and token == session_token

def allowed_file(filename):
    return any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

def validate_file_content(file_path, expected_ext):
    """Basic file type validation using magic bytes"""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
        
        # Image formats
        if expected_ext in ['.jpg', '.jpeg'] and header[:2] == b'\xff\xd8':
            return True
        if expected_ext == '.png' and header[:8] == b'\x89PNG\r\n\x1a\n':
            return True
        if expected_ext == '.gif' and header[:6] in [b'GIF87a', b'GIF89a']:
            return True
        
        # Video formats (basic check)
        if expected_ext in ['.mp4', '.mov', '.webm', '.mkv']:
            return True  # More complex validation needed for production
        
        # Audio formats
        if expected_ext in ['.mp3', '.wav', '.ogg']:
            return True  # More complex validation needed for production
        
        return False
    except:
        return False

def folder_size(folder):
    return sum(os.path.getsize(os.path.join(folder, f)) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f)))

def load_metadata():
    if not os.path.exists(METADATA_FILE):
        return []
    with open(METADATA_FILE, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except:
            return []

def save_metadata(data):
    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def add_metadata(record):
    with meta_lock:
        data = load_metadata()
        data.insert(0, record)  # newest first
        save_metadata(data)

def update_metadata_item(item_id, **kwargs):
    with meta_lock:
        data = load_metadata()
        for it in data:
            if it['id'] == item_id:
                it.update(kwargs)
                save_metadata(data)
                return it
    return None

def delete_metadata_item(item_id):
    with meta_lock:
        data = load_metadata()
        new = [it for it in data if it['id'] != item_id]
        save_metadata(new)
        return len(new) != len(data)

def generate_thumbnail_if_video(filepath, filename):
    # create thumbnail file path
    name_no_ext = os.path.splitext(filename)[0]
    thumb_path = os.path.join(THUMB_FOLDER, f"{name_no_ext}.jpg")
    # use ffmpeg to generate thumbnail - take frame at 1s
    try:
        subprocess.run([
            "ffmpeg", "-y", "-ss", "00:00:01", "-i", filepath,
            "-vframes", "1", "-q:v", "8", thumb_path
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return os.path.exists(thumb_path)
    except Exception:
        # ffmpeg might not be available; ignore silently
        return False

def stream_file_range(path):
    size = os.path.getsize(path)
    range_header = request.headers.get('Range', None)
    if not range_header:
        return send_file(path)
    m = re.search(r'bytes=(\d+)-(\d*)', range_header)
    if not m:
        return send_file(path)
    g = m.groups()
    byte1 = int(g[0])
    byte2 = int(g[1]) if g[1] else None
    if byte2:
        length = byte2 - byte1 + 1
    else:
        length = size - byte1
    with open(path, 'rb') as f:
        f.seek(byte1)
        chunk = f.read(length)
    rv = Response(chunk, 206, mimetype="application/octet-stream", direct_passthrough=True)
    rv.headers.add('Content-Range', f'bytes {byte1}-{byte1 + length - 1}/{size}')
    return rv

@socketio.on('connect')
def handle_connect():
    username = session.get('username', 'Anonymous')
    print(f"{username} connected")
    # send recent chat history to newly connected user
    chat_history = load_chat()
    emit('chat_history', chat_history)

@socketio.on('send_message')
def handle_send_message(data):
    """
    Accepts either:
    - plaintext: data['text']
    - encrypted: data['encrypted'] (base64 string)
    """
    try:
        username = session.get('username', 'Anonymous')
        timestamp = int(time.time())
        
        msg = {"user": username, "timestamp": timestamp}

        if 'encrypted' in data and data['encrypted']:
            msg['encrypted'] = data['encrypted'].strip()
        elif 'text' in data and data['text'].strip():
            msg['text'] = data['text'].strip()
        else:
            return  # empty message, ignore

        # load, append, keep last 100 messages
        chat_history = load_chat()
        chat_history.append(msg)
        chat_history = chat_history[-100:]
        save_chat(chat_history)

        emit('receive_message', msg, broadcast=True)
    except Exception as e:
        print(f"Error handling message: {e}")
        emit('error', {'msg': 'Failed to send message'}, room=request.sid)

# ----------------- Routes -----------------
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        if not check_rate_limit(client_ip):
            return "Too many login attempts. Please try again in 5 minutes.", 429
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if check_credentials(username, password):
            session['logged_in'] = True
            session['username'] = username
            session['csrf_token'] = secrets.token_hex(16)
            connected_users.add(username)
            clear_rate_limit(client_ip)
            return redirect(url_for('index'))
        else:
            return "Invalid credentials. Try again.", 401
    return render_template('login.html')

@app.route('/home', methods=['GET'])
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    username = session.get('username')
    files_meta = load_metadata()
    return render_template('index.html', files_meta=files_meta, username=username)

@app.route('/chat')
def chat():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    username = session.get('username')
    return render_template('chat.html', username=username)

# Upload endpoint (AJAX/XHR)
@app.route('/upload', methods=['POST'])
def upload():
    if not session.get('logged_in'):
        return jsonify({'status':'error','msg':'Not authenticated'}), 401
    if not validate_csrf_token():
        return jsonify({'status':'error','msg':'Invalid CSRF token'}), 403
    username = session.get('username')

    title = request.form.get('title', '').strip()
    if 'file' not in request.files:
        return jsonify({'status':'error','msg':'No file sent'}), 400
    file = request.files['file']
    orig_name = file.filename
    if not orig_name:
        return jsonify({'status':'error','msg':'Empty filename'}), 400
    if not allowed_file(orig_name):
        return jsonify({'status':'error','msg':'File type not allowed'}), 400

    # get size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size > MAX_FILE_SIZE:
        return jsonify({'status':'error','msg':'File exceeds 1GB limit'}), 400

    with folder_lock:
        if folder_size(UPLOAD_FOLDER) + file_size > MAX_FOLDER_SIZE:
            return jsonify({'status':'error','msg':'Server storage full (10GB)'}), 400

    # unique file id
    file_id = str(int(time.time())) + "_" + uuid.uuid4().hex[:8]
    ext = os.path.splitext(orig_name)[1]
    stored_filename = f"{file_id}{ext}"
    stored_path = os.path.join(UPLOAD_FOLDER, stored_filename)

    # save file in chunks (throttling stays if you want)
    # We'll do a direct save here because upload progress is shown client-side
    with open(stored_path, 'wb') as f:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
    
    # Validate file content matches extension
    if not validate_file_content(stored_path, ext):
        os.remove(stored_path)
        return jsonify({'status':'error','msg':'File content does not match extension'}), 400

    # generate thumbnail for videos (best-effort)
    is_video = ext.lower() in {'.mp4', '.mov', '.webm', '.mkv'}
    thumb_generated = False
    if is_video:
        thumb_generated = generate_thumbnail_if_video(stored_path, stored_filename)

    # create metadata record
    record = {
        "id": file_id,
        "stored_filename": stored_filename,
        "original_filename": orig_name,
        "uploader": username,
        "title": title or orig_name,
        "size": file_size,
        "mimetype": ext.lower().lstrip('.'),
        "timestamp": int(time.time()),
        "comments": []
    }
    add_metadata(record)

    return jsonify({'status':'ok','file_id': file_id, 'thumb': thumb_generated})

# Serve files (with Range support and thumbnail query)
@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    thumb = request.args.get('thumb') == '1'
    full_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(full_path):
        return abort(404)

    if thumb:
        name_no_ext = os.path.splitext(filename)[0]
        thumb_path = os.path.join(THUMB_FOLDER, f"{name_no_ext}.jpg")
        if os.path.exists(thumb_path):
            return send_file(thumb_path, mimetype='image/jpeg')
        else:
            # fallback placeholder
            placeholder = 'static/placeholder.jpg'
            return send_file(placeholder, mimetype='image/jpeg')

    # if video/audio, support Range streaming
    ext = os.path.splitext(filename)[1].lower()
    if ext in {'.mp4', '.mov', '.webm', '.mkv', '.mp3', '.wav', '.ogg'}:
        return stream_file_range(full_path)

    # images and others
    return send_file(full_path)

# Add comment
@app.route('/comment/<item_id>', methods=['POST'])
def comment(item_id):
    if not session.get('logged_in'):
        return jsonify({'status':'error'}), 401
    username = session.get('username')
    text = request.form.get('text', '').strip()
    if not text:
        return jsonify({'status':'error','msg':'Empty comment'}), 400
    with meta_lock:
        data = load_metadata()
        for it in data:
            if it['id'] == item_id:
                it.setdefault('comments', []).append({
                    'user': username, 'text': text, 'ts': int(time.time())
                })
                save_metadata(data)
                return jsonify({'status':'ok','comment':it['comments'][-1]})
    return jsonify({'status':'error','msg':'Item not found'}), 404

# Edit title (only uploader)
@app.route('/edit/<item_id>', methods=['POST'])
def edit(item_id):
    if not session.get('logged_in'):
        return jsonify({'status':'error'}), 401
    username = session.get('username')
    new_title = request.form.get('title', '').strip()
    if not new_title:
        return jsonify({'status':'error','msg':'Empty title'}), 400
    with meta_lock:
        data = load_metadata()
        for it in data:
            if it['id'] == item_id:
                if it['uploader'] != username:
                    return jsonify({'status':'error','msg':'Not allowed'}), 403
                it['title'] = new_title
                save_metadata(data)
                return jsonify({'status':'ok','title': new_title})
    return jsonify({'status':'error','msg':'Item not found'}), 404

# Delete (only uploader)
@app.route('/delete/<item_id>', methods=['POST'])
def delete(item_id):
    if not session.get('logged_in'):
        return jsonify({'status':'error'}), 401
    username = session.get('username')
    with meta_lock:
        data = load_metadata()
        found = None
        for it in data:
            if it['id'] == item_id:
                found = it
                break
        if not found:
            return jsonify({'status':'error','msg':'Not found'}), 404
        if found['uploader'] != username:
            return jsonify({'status':'error','msg':'Not allowed'}), 403
        # delete file
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, found['stored_filename']))
        except:
            pass
        # delete thumbnail if exists
        name_no_ext = os.path.splitext(found['stored_filename'])[0]
        try:
            os.remove(os.path.join(THUMB_FOLDER, f"{name_no_ext}.jpg"))
        except:
            pass
        # remove metadata
        new = [it for it in data if it['id'] != item_id]
        save_metadata(new)
        return jsonify({'status':'ok'})

# Fetch metadata (optional API)
@app.route('/metadata', methods=['GET'])
def metadata():
    return jsonify(load_metadata())

@app.route('/metadata_timestamp')
def metadata_timestamp():
    meta_file = 'metadata.json'  # path where you store your upload/comment data
    if not os.path.exists(meta_file):
        return jsonify({"timestamp": 0})
    mtime = os.path.getmtime(meta_file)
    return jsonify({"timestamp": mtime})

@app.route('/logout')
def logout():
    username = session.get('username')
    if username in connected_users:
        connected_users.remove(username)
    session.clear()
    return redirect(url_for('login'))

# ----------------- Run -----------------
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=True, log_output=True)
