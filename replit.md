# GenZ Bros - Social Media Platform

## Overview
GenZ Bros is a Flask-based social media platform with file sharing, gallery viewing, and real-time chat functionality. The application allows users to upload and share images, videos, and audio files, with support for encrypted messaging.

## Current State
The application has been successfully configured to run in the Replit environment. It's ready to use with the following features:
- User authentication system
- File upload/download (images, videos, audio)
- Media gallery with filtering
- Real-time chat with end-to-end encryption support
- Video thumbnail generation using FFmpeg

## Recent Changes (October 26, 2025)

### Initial Setup
- Installed Python 3.11 and required dependencies (Flask, Flask-SocketIO, python-socketio)
- Installed FFmpeg system dependency for video thumbnail generation
- Updated server configuration to bind to 0.0.0.0:5000 for Replit compatibility
- Added cache control headers to prevent browser caching issues
- Created users.csv with sample login credentials
- Updated .gitignore for Python environment files
- Configured Flask Server workflow
- Set up deployment configuration for autoscale

### Responsive Design Enhancements
- **Mobile-first responsive design** with comprehensive breakpoints:
  - Small mobile devices (320px - 360px)
  - Mobile phones (361px - 480px)
  - Tablets (481px - 768px)
  - Large tablets/small desktops (769px - 1024px)
  - Desktop (1024px+)
- **Improved touch targets**: All interactive elements (buttons, inputs) now meet accessibility standards with minimum 44-48px height on mobile
- **Better spacing and layout**: Optimized padding, margins, and gaps for each screen size
- **Fixed layout issues**: Resolved scrolling problems by implementing page-specific body classes (login-page, chat-page)
- **Enhanced header**: Responsive header with proper wrapping and text truncation for long usernames
- **Optimized gallery grid**: Dynamic grid columns that adapt to screen size (1 column on mobile, 2-3 on tablet, 4+ on desktop)
- **Improved modals**: Better modal sizing and positioning on mobile devices
- **Touch optimizations**: Added touch-action and -webkit-tap-highlight-color for smoother mobile interactions
- **File input improvements**: Better file selection display with visible filename on all devices

## Project Architecture

### Backend (Python/Flask)
- **server.py**: Main Flask application with routes, socket handlers, and business logic
- **Flask-SocketIO**: Real-time bidirectional communication for chat
- **File Storage**: Local file system with upload limits (1GB per file, 10GB total)

### Frontend
- **Templates**: Jinja2 templates in `/templates/` directory
  - `login.html`: User authentication page
  - `index.html`: Main feed/gallery page with upload functionality
  - `chat.html`: Real-time chat interface with encryption
- **Static Assets**: CSS files in `/static/css/`
- **JavaScript**: Client-side logic embedded in templates for chat, upload, and gallery interactions

### Data Storage
- **users.csv**: User credentials (username/password pairs)
- **metadata.json**: File upload metadata and comments
- **chat.json**: Chat message history (last 100 messages)
- **static/uploads/**: Uploaded media files
- **static/uploads/thumbs/**: Generated video thumbnails

## Features

### Authentication
- CSV-based user authentication
- Session management with Flask sessions
- Sample users:
  - admin/admin123
  - user1/password123
  - demo/demo

### File Upload & Gallery
- Support for images (JPG, PNG, GIF)
- Support for videos (MP4, MOV, WebM, MKV)
- Support for audio (MP3, WAV, OGG)
- Automatic video thumbnail generation
- File size limit: 1GB per file
- Total storage limit: 10GB
- Upload progress tracking
- Metadata tracking (uploader, title, timestamp)
- Comments on uploads
- Edit/delete functionality for uploaders

### Real-time Chat
- WebSocket-based messaging using Socket.IO
- Optional end-to-end encryption (AES-GCM with PBKDF2 key derivation)
- Media URL detection and embedding (images, videos, audio, YouTube, Vimeo)
- Last 100 messages retained
- Passphrase-based encryption for privacy

## Development

### Running Locally
The Flask Server workflow is configured to run automatically. It executes:
```bash
python server.py
```

### Dependencies
- Python 3.11
- Flask 3.1.2
- Flask-SocketIO 5.5.1
- python-socketio 5.14.2
- FFmpeg (system dependency)

### Configuration
- Host: 0.0.0.0 (accessible from all interfaces)
- Port: 5000
- Debug mode: Enabled (development only)
- CORS: Allowed for all origins (Socket.IO)
- Cache-Control: Disabled to prevent stale content

## Deployment
The application is configured for autoscale deployment, suitable for stateless web applications. The deployment will run `python server.py` and scale based on traffic.

## Security Notes
- Change the Flask secret key in `server.py` (currently set to 'your_secret_key_here')
- User passwords are stored in plain text in users.csv - consider implementing proper password hashing
- Chat encryption is optional and client-side only
- File uploads are not scanned for malicious content
- Production deployment should use a proper WSGI server (e.g., Gunicorn) instead of Flask's development server

## File Structure
```
.
├── server.py              # Main Flask application
├── users.csv              # User credentials
├── templates/             # HTML templates
│   ├── login.html        # Login page
│   ├── index.html        # Gallery/feed page
│   └── chat.html         # Chat page
├── static/
│   ├── css/              # Stylesheets
│   │   ├── base.css
│   │   ├── login.css
│   │   ├── index.css
│   │   └── chat.css
│   └── uploads/          # User-uploaded files (gitignored)
├── metadata.json         # Upload metadata (gitignored)
└── chat.json            # Chat history (gitignored)
```
