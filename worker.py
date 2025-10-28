import os
import sys
import time
import json
import subprocess
import shutil
from pathlib import Path
import db
import crypto_utils
from resource_monitor import ResourceMonitor

STORAGE_DIR = Path("storage/videos")
UPLOAD_FOLDER = Path("static/uploads")
TEMP_DIR = Path("temp")

STORAGE_DIR.mkdir(parents=True, exist_ok=True)
TEMP_DIR.mkdir(parents=True, exist_ok=True)

SEGMENT_DURATION = 6
FFMPEG_THREADS = 1

class VideoProcessor:
    """Process video files: decrypt, transcode to HLS, re-encrypt"""
    
    def __init__(self, job_id, video_id, group_passphrase):
        self.job_id = job_id
        self.video_id = video_id
        self.group_passphrase = group_passphrase
        self.video_dir = STORAGE_DIR / video_id
        self.video_dir.mkdir(parents=True, exist_ok=True)
        self.segments_dir = self.video_dir / "segments"
        self.segments_dir.mkdir(parents=True, exist_ok=True)
        
        salt = crypto_utils.generate_salt()
        self.master_key = crypto_utils.derive_master_key(group_passphrase, salt)
        self.content_key = crypto_utils.derive_content_key(self.master_key)
        self.salt = salt
    
    def process_video(self, encrypted_input_path, original_filename):
        """
        Process video: decrypt, transcode to HLS segments, re-encrypt
        
        Returns:
            Success boolean and error message if failed
        """
        try:
            db.update_job(self.job_id, status='processing', started_at=int(time.time()))
            
            temp_plain_path = TEMP_DIR / f"{self.video_id}_plain.tmp"
            
            print(f"[Job {self.job_id}] Step 1: Decrypting uploaded file...")
            self._decrypt_upload(encrypted_input_path, temp_plain_path)
            
            print(f"[Job {self.job_id}] Step 2: Transcoding to HLS segments...")
            segment_files = self._transcode_to_hls(temp_plain_path)
            
            print(f"[Job {self.job_id}] Step 3: Generating thumbnail...")
            thumb_path = self._generate_thumbnail(temp_plain_path)
            
            print(f"[Job {self.job_id}] Step 4: Re-encrypting segments...")
            manifest = self._encrypt_segments(segment_files)
            
            print(f"[Job {self.job_id}] Step 5: Encrypting manifest...")
            manifest_path = self._save_encrypted_manifest(manifest)
            
            print(f"[Job {self.job_id}] Step 6: Encrypting thumbnail...")
            if thumb_path:
                encrypted_thumb_path = self._encrypt_thumbnail(thumb_path)
            else:
                encrypted_thumb_path = None
            
            print(f"[Job {self.job_id}] Step 7: Cleaning up temp files...")
            if temp_plain_path.exists():
                temp_plain_path.unlink()
            
            db.update_video(
                self.video_id,
                status='ready',
                encrypted=True,
                salt=self.salt.hex(),
                manifest_path=str(manifest_path),
                thumb_path=str(encrypted_thumb_path) if encrypted_thumb_path else None
            )
            
            db.update_job(self.job_id, status='completed', finished_at=int(time.time()))
            
            print(f"[Job {self.job_id}] Processing completed successfully!")
            return True, None
            
        except Exception as e:
            error_msg = str(e)
            print(f"[Job {self.job_id}] Error: {error_msg}")
            db.update_job(self.job_id, status='failed', error_message=error_msg)
            return False, error_msg
    
    def _decrypt_upload(self, encrypted_path, output_path):
        """Decrypt uploaded file using per-chunk encryption metadata"""
        import json
        video = db.get_video(self.video_id)
        
        if not video.get('upload_encrypted'):
            shutil.copy(encrypted_path, output_path)
            return
        
        metadata = json.loads(video['encryption_metadata'])
        chunks_meta = metadata['chunks']
        
        encrypted_data = Path(encrypted_path).read_bytes()
        
        with open(output_path, 'wb') as f_out:
            offset = 0
            for chunk_meta in chunks_meta:
                iv = bytes.fromhex(chunk_meta['iv'])
                tag = bytes.fromhex(chunk_meta['tag'])
                chunk_size = chunk_meta['size']
                
                ciphertext = encrypted_data[offset:offset + chunk_size]
                offset += chunk_size
                
                combined = ciphertext + tag
                
                plaintext = crypto_utils.decrypt_aes_gcm(
                    ciphertext,
                    self.content_key,
                    iv,
                    tag
                )
                
                f_out.write(plaintext)
    
    def _transcode_to_hls(self, input_path):
        """
        Transcode video to HLS fMP4 segments
        
        Returns:
            List of segment file paths
        """
        segment_pattern = str(self.segments_dir / "seg_%03d.m4s")
        
        cmd = [
            'ffmpeg',
            '-i', str(input_path),
            '-c:v', 'libx264',
            '-preset', 'fast',
            '-crf', '23',
            '-c:a', 'aac',
            '-b:a', '128k',
            '-f', 'segment',
            '-segment_time', str(SEGMENT_DURATION),
            '-segment_format', 'mp4',
            '-segment_list', 'pipe:',
            '-threads', str(FFMPEG_THREADS),
            '-y',
            segment_pattern
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            raise Exception(f"FFmpeg failed: {e.stderr}")
        
        segment_files = sorted(self.segments_dir.glob("seg_*.m4s"))
        return segment_files
    
    def _generate_thumbnail(self, video_path):
        """Generate thumbnail from video"""
        thumb_path = self.video_dir / "thumb.jpg"
        
        cmd = [
            'ffmpeg',
            '-ss', '00:00:01',
            '-i', str(video_path),
            '-vframes', '1',
            '-q:v', '8',
            '-vf', 'scale=320:-1',
            '-y',
            str(thumb_path)
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, check=True)
            return thumb_path if thumb_path.exists() else None
        except subprocess.CalledProcessError:
            return None
    
    def _encrypt_segments(self, segment_files):
        """
        Encrypt each segment with deterministic IV
        
        Returns:
            Manifest dict with segment info
        """
        manifest = {
            'video_id': self.video_id,
            'segments': [],
            'kdf': {
                'method': 'PBKDF2',
                'iterations': crypto_utils.PBKDF2_ITERATIONS,
                'hash': 'SHA256'
            },
            'salt': self.salt.hex()
        }
        
        for idx, seg_file in enumerate(segment_files):
            seg_size = seg_file.stat().st_size
            
            iv = crypto_utils.derive_deterministic_iv(
                self.content_key,
                self.video_id,
                segment_index=idx
            )
            
            plaintext = seg_file.read_bytes()
            iv_ret, ciphertext, tag = crypto_utils.encrypt_aes_gcm(
                plaintext,
                self.content_key,
                iv=iv
            )
            
            encrypted_seg_path = self.segments_dir / f"seg_{idx:03d}.enc"
            encrypted_seg_path.write_bytes(iv_ret + tag + ciphertext)
            
            seg_file.unlink()
            
            manifest['segments'].append({
                'index': idx,
                'filename': encrypted_seg_path.name,
                'iv': iv.hex(),
                'size': len(ciphertext)
            })
        
        return manifest
    
    def _save_encrypted_manifest(self, manifest):
        """Save and encrypt manifest"""
        manifest_path = self.video_dir / "manifest.enc"
        
        encrypted_manifest = crypto_utils.encrypt_json(
            manifest,
            self.content_key,
            self.video_id,
            context="manifest"
        )
        
        manifest_path.write_text(encrypted_manifest)
        
        return manifest_path
    
    def _encrypt_thumbnail(self, thumb_path):
        """Encrypt thumbnail image"""
        encrypted_thumb_path = self.video_dir / "thumb.jpg.enc"
        
        iv = crypto_utils.derive_deterministic_iv(
            self.content_key,
            self.video_id,
            context="thumbnail"
        )
        
        plaintext = thumb_path.read_bytes()
        iv_ret, ciphertext, tag = crypto_utils.encrypt_aes_gcm(
            plaintext,
            self.content_key,
            iv=iv
        )
        
        encrypted_thumb_path.write_bytes(iv_ret + tag + ciphertext)
        
        thumb_path.unlink()
        
        return encrypted_thumb_path

class Worker:
    """Background worker for processing jobs"""
    
    def __init__(self, group_passphrase, poll_interval=5):
        self.group_passphrase = group_passphrase
        self.poll_interval = poll_interval
        self.running = True
        self.monitor = ResourceMonitor()
    
    def run(self):
        """Main worker loop"""
        print("Worker started. Polling for jobs...")
        
        while self.running:
            try:
                jobs = db.get_pending_jobs(limit=1)
                
                if not jobs:
                    time.sleep(self.poll_interval)
                    continue
                
                job = jobs[0]
                
                can_process, reason = self.monitor.can_process()
                if not can_process:
                    print(f"Cannot process job {job['job_id']}: {reason}")
                    db.update_job(job['job_id'], status='waiting_resource')
                    time.sleep(self.poll_interval * 2)
                    continue
                
                self.process_job(job)
                
            except KeyboardInterrupt:
                print("\nWorker stopping...")
                self.running = False
            except Exception as e:
                print(f"Worker error: {e}")
                time.sleep(self.poll_interval)
    
    def process_job(self, job):
        """Process a single job"""
        video = db.get_video(job['video_id'])
        if not video:
            print(f"Video {job['video_id']} not found")
            db.update_job(job['job_id'], status='failed', error_message='Video not found')
            return
        
        print(f"\nProcessing job {job['job_id']} for video {job['video_id']}...")
        
        input_path = UPLOAD_FOLDER / video['stored_filename']
        if not input_path.exists():
            print(f"Input file not found: {input_path}")
            db.update_job(job['job_id'], status='failed', error_message='Input file not found')
            return
        
        processor = VideoProcessor(
            job['job_id'],
            job['video_id'],
            self.group_passphrase
        )
        
        success, error = processor.process_video(input_path, video['original_filename'])
        
        if success:
            print(f"Job {job['job_id']} completed successfully")
        else:
            print(f"Job {job['job_id']} failed: {error}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python worker.py <group_passphrase>")
        sys.exit(1)
    
    passphrase = sys.argv[1]
    worker = Worker(passphrase)
    worker.run()
