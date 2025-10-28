import os
import time
import uuid
import base64
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify, Response
from flask_socketio import SocketIO, emit
import db
from resource_monitor import ResourceMonitor

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'dev_secret_key_change_in_production')
socketio = SocketIO(app, cors_allowed_origins="*", max_http_buffer_size=16*1024*1024)

db.init_db()

UPLOAD_FOLDER = Path('static/uploads')
STORAGE_DIR = Path('storage/videos')
TEMP_UPLOAD_DIR = Path('temp/uploads')

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
TEMP_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024
MAX_FOLDER_SIZE = 10 * 1024 * 1024 * 1024
CHUNK_SIZE = 4 * 1024 * 1024

@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        user = db.get_user(username)
        if user and user['password'] == password:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/home', methods=['GET'])
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    username = session.get('username')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per', 24))
    
    videos = db.get_videos(page=page, per_page=per_page)
    
    return render_template('index.html', videos=videos, username=username, page=page)

@app.route('/chat')
def chat():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    username = session.get('username')
    return render_template('chat.html', username=username)

@app.route('/api/videos', methods=['GET'])
def api_get_videos():
    """Get paginated video metadata"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per', 24))
    
    videos = db.get_videos(page=page, per_page=per_page)
    
    return jsonify({
        'videos': videos,
        'page': page,
        'per_page': per_page
    })

@app.route('/upload/init', methods=['POST'])
def upload_init():
    """Initialize chunked upload"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('username')
    data = request.get_json()
    
    filename = data.get('filename')
    filesize = data.get('filesize')
    mimetype = data.get('mimetype', '')
    title = data.get('title', filename)
    encrypted = data.get('encrypted', False)
    
    if not filename or not filesize:
        return jsonify({'error': 'Missing filename or filesize'}), 400
    
    if filesize > MAX_FILE_SIZE:
        return jsonify({'error': f'File too large. Max {MAX_FILE_SIZE/(1024*1024*1024)}GB'}), 400
    
    video_id = str(int(time.time())) + "_" + uuid.uuid4().hex[:8]
    ext = Path(filename).suffix
    stored_filename = f"{video_id}{ext}"
    
    upload_path = TEMP_UPLOAD_DIR / stored_filename
    upload_path.write_bytes(b'')
    
    session[f'upload_{video_id}'] = {
        'filename': stored_filename,
        'original_filename': filename,
        'filesize': filesize,
        'uploaded': 0,
        'encrypted': encrypted
    }
    
    return jsonify({
        'video_id': video_id,
        'chunk_size': CHUNK_SIZE
    })

@app.route('/upload/chunk/<video_id>', methods=['POST'])
def upload_chunk(video_id):
    """Upload a file chunk"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    upload_info = session.get(f'upload_{video_id}')
    if not upload_info:
        return jsonify({'error': 'Upload not initialized'}), 400
    
    chunk_index = int(request.form.get('chunk_index', 0))
    chunk_data = request.files.get('chunk')
    
    if not chunk_data:
        return jsonify({'error': 'No chunk data'}), 400
    
    stored_filename = upload_info['filename']
    upload_path = TEMP_UPLOAD_DIR / stored_filename
    
    with open(upload_path, 'ab') as f:
        chunk_data.save(f)
    
    upload_info['uploaded'] = upload_path.stat().st_size
    session[f'upload_{video_id}'] = upload_info
    session.modified = True
    
    return jsonify({
        'uploaded': upload_info['uploaded'],
        'total': upload_info['filesize'],
        'percent': int((upload_info['uploaded'] / upload_info['filesize']) * 100)
    })

@app.route('/upload/complete', methods=['POST'])
def upload_complete():
    """Finalize upload and create processing job"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('username')
    data = request.get_json()
    
    video_id = data.get('video_id')
    title = data.get('title', '')
    encryption_metadata = data.get('encryption_metadata')
    
    upload_info = session.get(f'upload_{video_id}')
    if not upload_info:
        return jsonify({'error': 'Upload not found'}), 400
    
    stored_filename = upload_info['filename']
    temp_path = TEMP_UPLOAD_DIR / stored_filename
    final_path = UPLOAD_FOLDER / stored_filename
    
    if not temp_path.exists():
        return jsonify({'error': 'Upload file not found'}), 400
    
    temp_path.rename(final_path)
    
    ext = Path(upload_info['original_filename']).suffix.lower().lstrip('.')
    
    db.create_video(
        video_id=video_id,
        stored_filename=stored_filename,
        original_filename=upload_info['original_filename'],
        owner=username,
        title=title or upload_info['original_filename'],
        size=upload_info['filesize'],
        mimetype=ext,
        timestamp=int(time.time())
    )
    
    if upload_info.get('encrypted') and encryption_metadata:
        db.update_video(
            video_id,
            upload_encrypted=True,
            encryption_metadata=encryption_metadata
        )
    
    job_id = db.create_job(video_id, 'process_video', priority=0)
    
    monitor = ResourceMonitor()
    eta = monitor.estimate_processing_time(upload_info['filesize'])
    db.update_job(job_id, eta_seconds=eta)
    
    session.pop(f'upload_{video_id}', None)
    session.modified = True
    
    socketio.emit('upload_complete', {
        'video_id': video_id,
        'job_id': job_id,
        'eta_seconds': eta
    }, room=request.sid)
    
    return jsonify({
        'status': 'success',
        'video_id': video_id,
        'job_id': job_id,
        'eta_seconds': eta
    })

@app.route('/video/<video_id>/manifest', methods=['GET'])
def get_manifest(video_id):
    """Serve encrypted manifest"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    video = db.get_video(video_id)
    if not video:
        return jsonify({'error': 'Video not found'}), 404
    
    if not video.get('manifest_path'):
        return jsonify({'error': 'Manifest not ready'}), 404
    
    manifest_path = Path(video['manifest_path'])
    if not manifest_path.exists():
        return jsonify({'error': 'Manifest file not found'}), 404
    
    return send_file(manifest_path, mimetype='application/octet-stream')

@app.route('/video/<video_id>/segment/<segment_name>', methods=['GET'])
def get_segment(video_id, segment_name):
    """Serve encrypted video segment"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    video = db.get_video(video_id)
    if not video:
        return jsonify({'error': 'Video not found'}), 404
    
    segment_path = STORAGE_DIR / video_id / "segments" / segment_name
    if not segment_path.exists():
        return jsonify({'error': 'Segment not found'}), 404
    
    response = send_file(segment_path, mimetype='application/octet-stream')
    response.headers['Cache-Control'] = 'public, max-age=31536000'
    return response

@app.route('/video/<video_id>/thumbnail', methods=['GET'])
def get_thumbnail(video_id):
    """Serve encrypted thumbnail"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    video = db.get_video(video_id)
    if not video:
        return jsonify({'error': 'Video not found'}), 404
    
    if not video.get('thumb_path'):
        return jsonify({'error': 'Thumbnail not ready'}), 404
    
    thumb_path = Path(video['thumb_path'])
    if not thumb_path.exists():
        return jsonify({'error': 'Thumbnail not found'}), 404
    
    return send_file(thumb_path, mimetype='application/octet-stream')

@app.route('/comment/<video_id>', methods=['POST'])
def add_comment(video_id):
    """Add comment to video"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('username')
    text = request.form.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Empty comment'}), 400
    
    comment = db.add_comment(video_id, username, text, int(time.time()))
    
    return jsonify({'status': 'success', 'comment': comment})

@app.route('/edit/<video_id>', methods=['POST'])
def edit_video(video_id):
    """Edit video title"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('username')
    new_title = request.form.get('title', '').strip()
    
    if not new_title:
        return jsonify({'error': 'Empty title'}), 400
    
    video = db.get_video(video_id)
    if not video:
        return jsonify({'error': 'Video not found'}), 404
    
    if video['owner'] != username:
        return jsonify({'error': 'Not authorized'}), 403
    
    db.update_video(video_id, title=new_title)
    
    return jsonify({'status': 'success', 'title': new_title})

@app.route('/delete/<video_id>', methods=['POST'])
def delete_video(video_id):
    """Delete video"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session.get('username')
    video = db.get_video(video_id)
    
    if not video:
        return jsonify({'error': 'Video not found'}), 404
    
    if video['owner'] != username:
        return jsonify({'error': 'Not authorized'}), 403
    
    upload_path = UPLOAD_FOLDER / video['stored_filename']
    if upload_path.exists():
        upload_path.unlink()
    
    video_dir = STORAGE_DIR / video_id
    if video_dir.exists():
        import shutil
        shutil.rmtree(video_dir)
    
    db.delete_video(video_id)
    
    return jsonify({'status': 'success'})

@app.route('/job/<int:job_id>/status', methods=['GET'])
def get_job_status(job_id):
    """Get job status"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Not authenticated'}), 401
    
    job = db.get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    return jsonify(job)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    username = session.get('username', 'Anonymous')
    print(f"{username} connected via WebSocket")

@socketio.on('send_message')
def handle_send_message(data):
    """Handle chat messages (existing functionality)"""
    username = session.get('username', 'Anonymous')
    timestamp = int(time.time())
    
    msg = {"user": username, "timestamp": timestamp}
    
    if 'encrypted' in data and data['encrypted']:
        msg['encrypted'] = data['encrypted'].strip()
    elif 'text' in data and data['text'].strip():
        msg['text'] = data['text'].strip()
    else:
        return
    
    emit('receive_message', msg, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=9000, debug=True, use_reloader=True)
