import sqlite3
import json
import os
from threading import Lock
from contextlib import contextmanager

DB_PATH = 'app_data.db'
db_lock = Lock()

@contextmanager
def get_db():
    """Context manager for database connections with automatic commit/rollback"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initialize database schema"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                created_at INTEGER DEFAULT (strftime('%s', 'now'))
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS videos (
                video_id TEXT PRIMARY KEY,
                stored_filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                owner TEXT NOT NULL,
                title TEXT NOT NULL,
                size INTEGER NOT NULL,
                mimetype TEXT NOT NULL,
                status TEXT DEFAULT 'uploaded',
                created_at INTEGER NOT NULL,
                updated_at INTEGER DEFAULT (strftime('%s', 'now')),
                salt TEXT,
                manifest_path TEXT,
                thumb_path TEXT,
                encrypted BOOLEAN DEFAULT 0,
                upload_iv TEXT,
                upload_tag TEXT,
                upload_encrypted BOOLEAN DEFAULT 0,
                encryption_metadata TEXT,
                FOREIGN KEY (owner) REFERENCES users(username)
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_videos_owner ON videos(owner)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_videos_created ON videos(created_at DESC)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_videos_status ON videos(status)
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                video_id TEXT NOT NULL,
                username TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (video_id) REFERENCES videos(video_id) ON DELETE CASCADE,
                FOREIGN KEY (username) REFERENCES users(username)
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_comments_video ON comments(video_id)
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS jobs (
                job_id INTEGER PRIMARY KEY AUTOINCREMENT,
                video_id TEXT NOT NULL,
                job_type TEXT NOT NULL,
                status TEXT DEFAULT 'queued',
                priority INTEGER DEFAULT 0,
                attempts INTEGER DEFAULT 0,
                queued_at INTEGER NOT NULL,
                started_at INTEGER,
                finished_at INTEGER,
                eta_seconds INTEGER,
                error_message TEXT,
                FOREIGN KEY (video_id) REFERENCES videos(video_id) ON DELETE CASCADE
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_jobs_priority ON jobs(priority DESC, queued_at ASC)
        ''')
        
        conn.commit()

def migrate_from_json():
    """Migrate existing metadata.json and users.csv to SQLite"""
    if not os.path.exists('metadata.json') and not os.path.exists('users.csv'):
        return
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        if os.path.exists('users.csv'):
            import csv
            with open('users.csv', 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cursor.execute('''
                        INSERT OR IGNORE INTO users (username, password)
                        VALUES (?, ?)
                    ''', (row['username'], row['password']))
        
        if os.path.exists('metadata.json'):
            with open('metadata.json', 'r') as f:
                try:
                    metadata = json.load(f)
                except:
                    metadata = []
            
            for item in metadata:
                cursor.execute('''
                    INSERT OR IGNORE INTO videos 
                    (video_id, stored_filename, original_filename, owner, title, 
                     size, mimetype, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', ?)
                ''', (
                    item['id'],
                    item['stored_filename'],
                    item['original_filename'],
                    item['uploader'],
                    item['title'],
                    item['size'],
                    item['mimetype'],
                    item['timestamp']
                ))
                
                for comment in item.get('comments', []):
                    cursor.execute('''
                        INSERT INTO comments (video_id, username, text, created_at)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        item['id'],
                        comment['user'],
                        comment['text'],
                        comment['ts']
                    ))
        
        conn.commit()

def get_user(username):
    """Get user by username"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        return cursor.fetchone()

def create_user(username, password):
    """Create a new user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password)
            VALUES (?, ?)
        ''', (username, password))
        return True

def get_videos(page=1, per_page=24, owner=None):
    """Get paginated videos"""
    offset = (page - 1) * per_page
    with get_db() as conn:
        cursor = conn.cursor()
        if owner:
            cursor.execute('''
                SELECT * FROM videos 
                WHERE owner = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            ''', (owner, per_page, offset))
        else:
            cursor.execute('''
                SELECT * FROM videos 
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            ''', (per_page, offset))
        
        videos = []
        for row in cursor.fetchall():
            video = dict(row)
            cursor.execute('''
                SELECT * FROM comments 
                WHERE video_id = ?
                ORDER BY created_at ASC
            ''', (video['video_id'],))
            video['comments'] = [dict(c) for c in cursor.fetchall()]
            videos.append(video)
        
        return videos

def get_video(video_id):
    """Get a single video with comments"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM videos WHERE video_id = ?', (video_id,))
        video = cursor.fetchone()
        if not video:
            return None
        
        video = dict(video)
        cursor.execute('''
            SELECT * FROM comments 
            WHERE video_id = ?
            ORDER BY created_at ASC
        ''', (video_id,))
        video['comments'] = [dict(c) for c in cursor.fetchall()]
        return video

def create_video(video_id, stored_filename, original_filename, owner, title, size, mimetype, timestamp):
    """Create a new video record"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO videos 
            (video_id, stored_filename, original_filename, owner, title, size, mimetype, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'uploaded')
        ''', (video_id, stored_filename, original_filename, owner, title, size, mimetype, timestamp))
        return True

def update_video(video_id, **kwargs):
    """Update video fields"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        allowed_fields = ['title', 'status', 'salt', 'manifest_path', 'thumb_path', 'encrypted', 
                         'upload_iv', 'upload_tag', 'upload_encrypted', 'encryption_metadata']
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys() if k in allowed_fields])
        values = [v for k, v in kwargs.items() if k in allowed_fields]
        
        if not set_clause:
            return False
        
        values.append(video_id)
        cursor.execute(f'''
            UPDATE videos 
            SET {set_clause}, updated_at = strftime('%s', 'now')
            WHERE video_id = ?
        ''', values)
        
        return cursor.rowcount > 0

def delete_video(video_id):
    """Delete a video and its comments"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM videos WHERE video_id = ?', (video_id,))
        return cursor.rowcount > 0

def add_comment(video_id, username, text, timestamp):
    """Add a comment to a video"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO comments (video_id, username, text, created_at)
            VALUES (?, ?, ?, ?)
        ''', (video_id, username, text, timestamp))
        
        cursor.execute('''
            SELECT * FROM comments WHERE comment_id = ?
        ''', (cursor.lastrowid,))
        return dict(cursor.fetchone())

def create_job(video_id, job_type, priority=0):
    """Create a processing job"""
    import time
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO jobs (video_id, job_type, priority, queued_at)
            VALUES (?, ?, ?, ?)
        ''', (video_id, job_type, priority, int(time.time())))
        return cursor.lastrowid

def get_job(job_id):
    """Get a job by ID"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM jobs WHERE job_id = ?', (job_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_pending_jobs(limit=10):
    """Get pending jobs ordered by priority and queue time"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM jobs 
            WHERE status IN ('queued', 'waiting_resource')
            ORDER BY priority DESC, queued_at ASC
            LIMIT ?
        ''', (limit,))
        return [dict(row) for row in cursor.fetchall()]

def update_job(job_id, **kwargs):
    """Update job fields"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        allowed_fields = ['status', 'started_at', 'finished_at', 'eta_seconds', 'attempts', 'error_message']
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys() if k in allowed_fields])
        values = [v for k, v in kwargs.items() if k in allowed_fields]
        
        if not set_clause:
            return False
        
        values.append(job_id)
        cursor.execute(f'''
            UPDATE jobs 
            SET {set_clause}
            WHERE job_id = ?
        ''', values)
        
        return cursor.rowcount > 0

if __name__ == '__main__':
    init_db()
    migrate_from_json()
    print("Database initialized and migration completed!")
