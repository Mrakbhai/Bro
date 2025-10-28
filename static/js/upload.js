// Chunked upload with encryption

class ChunkedUploader {
    constructor(file, options = {}) {
        this.file = file;
        this.videoId = null;
        this.chunkSize = options.chunkSize || (4 * 1024 * 1024);
        this.encrypted = options.encrypted || false;
        this.title = options.title || file.name;
        this.onProgress = options.onProgress || (() => {});
        this.onComplete = options.onComplete || (() => {});
        this.onError = options.onError || ((err) => console.error(err));
        
        this.uploadedBytes = 0;
        this.totalBytes = file.size;
        this.encryptedData = null;
    }

    async start() {
        try {
            if (this.encrypted && window.cryptoManager) {
                this.onProgress({
                    phase: 'encrypting',
                    percent: 0,
                    message: 'Encrypting file...'
                });
                
                this.encryptedData = await window.cryptoManager.encryptFile(
                    this.file,
                    (encrypted, total) => {
                        this.onProgress({
                            phase: 'encrypting',
                            percent: Math.round((encrypted / total) * 50),
                            message: 'Encrypting file...'
                        });
                    }
                );
                
                this.totalBytes = this.encryptedData.ciphertext.length;
            }
            
            await this.initUpload();
            
            await this.uploadChunks();
            
            await this.completeUpload();
            
        } catch (error) {
            this.onError(error);
        }
    }

    async initUpload() {
        const response = await fetch('/upload/init', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename: this.file.name,
                filesize: this.totalBytes,
                mimetype: this.file.type,
                title: this.title,
                encrypted: this.encrypted
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to initialize upload');
        }

        const data = await response.json();
        this.videoId = data.video_id;
        this.chunkSize = data.chunk_size;
    }

    async uploadChunks() {
        const dataToUpload = this.encrypted 
            ? this.encryptedData.ciphertext 
            : await this.file.arrayBuffer();
        
        const totalChunks = Math.ceil(this.totalBytes / this.chunkSize);
        
        for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
            const start = chunkIndex * this.chunkSize;
            const end = Math.min(start + this.chunkSize, this.totalBytes);
            
            const chunk = this.encrypted
                ? dataToUpload.slice(start, end)
                : new Uint8Array(dataToUpload, start, end - start);
            
            const formData = new FormData();
            formData.append('chunk_index', chunkIndex);
            formData.append('chunk', new Blob([chunk]));
            
            const response = await fetch(`/upload/chunk/${this.videoId}`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Chunk upload failed');
            }

            const data = await response.json();
            this.uploadedBytes = data.uploaded;
            
            const basePercent = this.encrypted ? 50 : 0;
            const uploadPercent = Math.round((this.uploadedBytes / this.totalBytes) * 50);
            
            this.onProgress({
                phase: 'uploading',
                percent: basePercent + uploadPercent,
                uploaded: this.uploadedBytes,
                total: this.totalBytes,
                chunk: chunkIndex + 1,
                totalChunks: totalChunks,
                message: `Uploading chunk ${chunkIndex + 1}/${totalChunks}...`
            });
        }
    }

    async completeUpload() {
        const payload = {
            video_id: this.videoId,
            title: this.title
        };
        
        if (this.encrypted && this.encryptedData) {
            payload.encryption_metadata = JSON.stringify(this.encryptedData.metadata);
        }
        
        const response = await fetch('/upload/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to complete upload');
        }

        const data = await response.json();
        
        this.onProgress({
            phase: 'complete',
            percent: 100,
            message: 'Upload complete! Processing...'
        });
        
        this.onComplete(data);
    }
}

window.ChunkedUploader = ChunkedUploader;
