// Encrypted HLS video player using MediaSource API

class EncryptedVideoPlayer {
    constructor(videoElement, videoId) {
        this.videoElement = videoElement;
        this.videoId = videoId;
        this.manifest = null;
        this.mediaSource = null;
        this.sourceBuffer = null;
        this.currentSegment = 0;
        this.segmentsLoaded = new Set();
        this.prefetchBuffer = 3;
        this.isPlaying = false;
    }

    async initialize() {
        try {
            const manifestBlob = await this.fetchManifest();
            this.manifest = await window.cryptoManager.decryptManifest(manifestBlob);
            
            console.log('Manifest loaded:', this.manifest);
            
            if ('MediaSource' in window) {
                await this.setupMediaSource();
            } else {
                throw new Error('MediaSource API not supported');
            }
            
        } catch (error) {
            console.error('Failed to initialize player:', error);
            throw error;
        }
    }

    async fetchManifest() {
        const response = await fetch(`/video/${this.videoId}/manifest`);
        if (!response.ok) {
            throw new Error('Failed to fetch manifest');
        }
        return new Uint8Array(await response.arrayBuffer());
    }

    async setupMediaSource() {
        this.mediaSource = new MediaSource();
        this.videoElement.src = URL.createObjectURL(this.mediaSource);
        
        return new Promise((resolve, reject) => {
            this.mediaSource.addEventListener('sourceopen', async () => {
                try {
                    this.sourceBuffer = this.mediaSource.addSourceBuffer('video/mp4; codecs="avc1.42E01E,mp4a.40.2"');
                    
                    this.sourceBuffer.addEventListener('updateend', () => {
                        this.loadNextSegments();
                    });
                    
                    await this.loadNextSegments();
                    resolve();
                    
                } catch (error) {
                    reject(error);
                }
            });
            
            this.mediaSource.addEventListener('sourceended', () => {
                console.log('Playback ended');
            });
            
            this.videoElement.addEventListener('timeupdate', () => {
                this.onTimeUpdate();
            });
        });
    }

    async loadNextSegments() {
        if (this.sourceBuffer.updating) {
            return;
        }
        
        const segmentsToLoad = [];
        for (let i = 0; i < this.prefetchBuffer; i++) {
            const segmentIndex = this.currentSegment + i;
            if (segmentIndex < this.manifest.segments.length && 
                !this.segmentsLoaded.has(segmentIndex)) {
                segmentsToLoad.push(segmentIndex);
            }
        }
        
        if (segmentsToLoad.length === 0) {
            if (this.currentSegment >= this.manifest.segments.length) {
                if (this.mediaSource.readyState === 'open') {
                    this.mediaSource.endOfStream();
                }
            }
            return;
        }
        
        try {
            const segmentIndex = segmentsToLoad[0];
            const segmentData = await this.loadSegment(segmentIndex);
            
            if (segmentData && !this.sourceBuffer.updating) {
                this.sourceBuffer.appendBuffer(segmentData);
                this.segmentsLoaded.add(segmentIndex);
                this.currentSegment = Math.max(this.currentSegment, segmentIndex + 1);
            }
        } catch (error) {
            console.error('Failed to load segment:', error);
        }
    }

    async loadSegment(index) {
        try {
            const segment = this.manifest.segments[index];
            if (!segment) {
                return null;
            }
            
            const response = await fetch(`/video/${this.videoId}/segment/${segment.filename}`);
            if (!response.ok) {
                throw new Error(`Failed to fetch segment ${index}`);
            }
            
            const encryptedSegment = new Uint8Array(await response.arrayBuffer());
            
            const decryptedSegment = await window.cryptoManager.decryptSegment(encryptedSegment);
            
            return decryptedSegment;
            
        } catch (error) {
            console.error(`Error loading segment ${index}:`, error);
            throw error;
        }
    }

    onTimeUpdate() {
        const currentTime = this.videoElement.currentTime;
        const segmentDuration = 6;
        const expectedSegment = Math.floor(currentTime / segmentDuration);
        
        if (expectedSegment > this.currentSegment - this.prefetchBuffer) {
            this.loadNextSegments();
        }
    }

    play() {
        this.isPlaying = true;
        return this.videoElement.play();
    }

    pause() {
        this.isPlaying = false;
        this.videoElement.pause();
    }

    destroy() {
        if (this.mediaSource && this.mediaSource.readyState === 'open') {
            this.mediaSource.endOfStream();
        }
        if (this.videoElement.src) {
            URL.revokeObjectURL(this.videoElement.src);
        }
    }
}

async function loadEncryptedThumbnail(videoId, imgElement) {
    try {
        const response = await fetch(`/video/${videoId}/thumbnail`);
        if (!response.ok) {
            throw new Error('Failed to fetch thumbnail');
        }
        
        const encryptedThumb = new Uint8Array(await response.arrayBuffer());
        const decryptedThumb = await window.cryptoManager.decryptBlob(encryptedThumb);
        
        const blob = new Blob([decryptedThumb], { type: 'image/jpeg' });
        const url = URL.createObjectURL(blob);
        
        imgElement.src = url;
        imgElement.onload = () => URL.revokeObjectURL(url);
        
    } catch (error) {
        console.error('Failed to load thumbnail:', error);
        imgElement.src = '/static/placeholder.jpg';
    }
}

window.EncryptedVideoPlayer = EncryptedVideoPlayer;
window.loadEncryptedThumbnail = loadEncryptedThumbnail;
