// Client-side encryption utilities using WebCrypto API

const PBKDF2_ITERATIONS = 150000;
const KEY_LENGTH = 256;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

class CryptoManager {
    constructor() {
        this.passphrase = null;
        this.masterKey = null;
        this.contentKey = null;
        this.salt = null;
    }

    async setPassphrase(passphrase, saltHex = null) {
        this.passphrase = passphrase;
        
        if (saltHex) {
            this.salt = this.hexToBytes(saltHex);
        } else {
            this.salt = crypto.getRandomValues(new Uint8Array(16));
        }
        
        this.masterKey = await this.deriveMasterKey(passphrase, this.salt);
        this.contentKey = await this.deriveContentKey(this.masterKey);
        
        return this.salt;
    }

    async deriveMasterKey(passphrase, salt) {
        const encoder = new TextEncoder();
        const passphraseKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(passphrase),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        const masterKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            passphraseKey,
            { name: 'AES-GCM', length: KEY_LENGTH },
            true,
            ['encrypt', 'decrypt']
        );

        return masterKey;
    }

    async deriveContentKey(masterKey) {
        const masterKeyBytes = await crypto.subtle.exportKey('raw', masterKey);
        
        const hkdfKey = await crypto.subtle.importKey(
            'raw',
            masterKeyBytes,
            'HKDF',
            false,
            ['deriveBits']
        );

        const contentKeyBits = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(0),
                info: new TextEncoder().encode('content-key')
            },
            hkdfKey,
            KEY_LENGTH
        );

        const contentKey = await crypto.subtle.importKey(
            'raw',
            contentKeyBits,
            'AES-GCM',
            true,
            ['encrypt', 'decrypt']
        );

        return contentKey;
    }

    async deriveDeterministicIV(videoId, segmentIndex = null, context = 'segment') {
        const encoder = new TextEncoder();
        const contentKeyBytes = await crypto.subtle.exportKey('raw', this.contentKey);
        
        let data;
        if (segmentIndex !== null) {
            data = encoder.encode(`${videoId}:${segmentIndex}`);
        } else {
            data = encoder.encode(`${videoId}:${context}`);
        }

        const hmacKey = await crypto.subtle.importKey(
            'raw',
            contentKeyBytes,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        const signature = await crypto.subtle.sign('HMAC', hmacKey, data);
        return new Uint8Array(signature).slice(0, IV_LENGTH);
    }

    async encryptFile(file, onProgress = null) {
        const chunkSize = 4 * 1024 * 1024;
        const totalChunks = Math.ceil(file.size / chunkSize);
        
        const encryptedChunks = [];
        const chunkMetadata = [];
        let offset = 0;
        let chunkIndex = 0;
        
        while (offset < file.size) {
            const chunk = file.slice(offset, offset + chunkSize);
            const arrayBuffer = await chunk.arrayBuffer();
            
            const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
            
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv, tagLength: TAG_LENGTH * 8 },
                this.contentKey,
                arrayBuffer
            );
            
            const encryptedArray = new Uint8Array(encrypted);
            const tag = encryptedArray.slice(-TAG_LENGTH);
            const ciphertext = encryptedArray.slice(0, -TAG_LENGTH);
            
            encryptedChunks.push(ciphertext);
            chunkMetadata.push({
                index: chunkIndex,
                iv: this.bytesToHex(iv),
                tag: this.bytesToHex(tag),
                size: ciphertext.length
            });
            
            offset += chunkSize;
            chunkIndex++;
            
            if (onProgress) {
                onProgress(offset, file.size);
            }
        }
        
        const totalSize = encryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const combined = new Uint8Array(totalSize);
        let position = 0;
        
        for (const chunk of encryptedChunks) {
            combined.set(chunk, position);
            position += chunk.length;
        }
        
        return {
            ciphertext: combined,
            metadata: {
                chunks: chunkMetadata,
                totalChunks: totalChunks
            }
        };
    }

    async decryptBlob(encryptedData) {
        const iv = encryptedData.slice(0, IV_LENGTH);
        const tag = encryptedData.slice(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
        const ciphertext = encryptedData.slice(IV_LENGTH + TAG_LENGTH);
        
        const combined = new Uint8Array(ciphertext.length + tag.length);
        combined.set(ciphertext, 0);
        combined.set(tag, ciphertext.length);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv, tagLength: TAG_LENGTH * 8 },
            this.contentKey,
            combined
        );
        
        return new Uint8Array(decrypted);
    }

    async decryptManifest(encryptedBlob) {
        const decrypted = await this.decryptBlob(encryptedBlob);
        const text = new TextDecoder().decode(decrypted);
        return JSON.parse(text);
    }

    async decryptSegment(encryptedSegment) {
        return await this.decryptBlob(encryptedSegment);
    }

    bytesToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    async encryptText(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv, tagLength: TAG_LENGTH * 8 },
            this.contentKey,
            data
        );
        
        const encryptedArray = new Uint8Array(encrypted);
        const tag = encryptedArray.slice(-TAG_LENGTH);
        const ciphertext = encryptedArray.slice(0, -TAG_LENGTH);
        
        const combined = new Uint8Array(IV_LENGTH + TAG_LENGTH + ciphertext.length);
        combined.set(iv, 0);
        combined.set(tag, IV_LENGTH);
        combined.set(ciphertext, IV_LENGTH + TAG_LENGTH);
        
        return btoa(String.fromCharCode.apply(null, combined));
    }

    async decryptText(encryptedBase64) {
        const encryptedBytes = new Uint8Array(
            atob(encryptedBase64).split('').map(c => c.charCodeAt(0))
        );
        
        const decrypted = await this.decryptBlob(encryptedBytes);
        return new TextDecoder().decode(decrypted);
    }
}

const cryptoManager = new CryptoManager();

async function promptForPassphrase() {
    const passphrase = localStorage.getItem('group_passphrase');
    
    if (passphrase) {
        await cryptoManager.setPassphrase(passphrase);
        return true;
    }
    
    const modal = document.createElement('div');
    modal.id = 'passphrase-modal';
    modal.innerHTML = `
        <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
                    background: rgba(0,0,0,0.8); display: flex; align-items: center; 
                    justify-content: center; z-index: 10000;">
            <div style="background: #1a1a2e; padding: 30px; border-radius: 10px; max-width: 400px; width: 90%;">
                <h2 style="color: #16f4d0; margin-bottom: 20px;">Enter Passphrase</h2>
                <p style="color: #94a1b2; margin-bottom: 20px;">
                    This passphrase is used to encrypt and decrypt all content. 
                    Keep it secure and share it only with trusted friends.
                </p>
                <input type="password" id="passphrase-input" 
                       style="width: 100%; padding: 12px; margin-bottom: 20px; 
                              background: #16213e; border: 1px solid #0f3460; 
                              color: white; border-radius: 5px;"
                       placeholder="Enter group passphrase">
                <div style="display: flex; gap: 10px;">
                    <button id="passphrase-submit" 
                            style="flex: 1; padding: 12px; background: #16f4d0; 
                                   color: #0f1419; border: none; border-radius: 5px; 
                                   cursor: pointer; font-weight: bold;">
                        Unlock
                    </button>
                    <button id="passphrase-cancel" 
                            style="flex: 1; padding: 12px; background: #e94560; 
                                   color: white; border: none; border-radius: 5px; 
                                   cursor: pointer;">
                        Cancel
                    </button>
                </div>
                <label style="color: #94a1b2; margin-top: 15px; display: block;">
                    <input type="checkbox" id="remember-passphrase"> Remember passphrase
                </label>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    return new Promise((resolve) => {
        const input = document.getElementById('passphrase-input');
        const submit = document.getElementById('passphrase-submit');
        const cancel = document.getElementById('passphrase-cancel');
        const remember = document.getElementById('remember-passphrase');
        
        const handleSubmit = async () => {
            const passphrase = input.value.trim();
            if (!passphrase) {
                alert('Please enter a passphrase');
                return;
            }
            
            await cryptoManager.setPassphrase(passphrase);
            
            if (remember.checked) {
                localStorage.setItem('group_passphrase', passphrase);
            }
            
            modal.remove();
            resolve(true);
        };
        
        submit.onclick = handleSubmit;
        input.onkeypress = (e) => {
            if (e.key === 'Enter') handleSubmit();
        };
        
        cancel.onclick = () => {
            modal.remove();
            resolve(false);
        };
        
        input.focus();
    });
}

window.cryptoManager = cryptoManager;
window.promptForPassphrase = promptForPassphrase;
