// handshake.js
import { DoubleRatchet } from './crypto_ratchet.js';

export class HandshakeManager {
    /**
     * @param {WebSocket} websocket The active WebSocket connection to the local Daemon
     * @param {Function} onMessageDecrypted Callback fired when a decrypted message is ready for the UI
     * @param {Function} onHandshakeEstablished Callback fired when the handshake is complete
     */
    constructor(websocket, onMessageDecrypted, onHandshakeEstablished) {
        this.ws = websocket;
        this.onMessageDecrypted = onMessageDecrypted;
        this.onHandshakeEstablished = onHandshakeEstablished;
        this.ratchet = new DoubleRatchet();
        this.state = 'IDLE'; // IDLE, WAITING_FOR_ACCEPT, ESTABLISHED
        this.tempKeyPair = null; // Holds temporary P-384 keys during the handshake
        this.ourRawPubKey = null;
        this.theirRawPubKey = null;
        this.isInitiator = false;
        
        // Attach listener to WebSocket
        this.ws.addEventListener('message', async (event) => {
            try {
                // We only care about JSON payloads for the Handshake and Ratchet
                if (typeof event.data !== 'string' || !event.data.startsWith('{')) return;
                await this.handleIncomingMessage(event.data);
            } catch (e) {
                console.error("[HandshakeManager] Error processing incoming message:", e);
            }
        });
    }

    /**
     * Initiates the Synchronous Handshake by sending an OFFER packet.
     */
    async initiateHandshake() {
        if (this.state !== 'IDLE') throw new Error("Handshake already in progress or established.");
        
        console.log("[Handshake] Initiating Handshake... Generating temporary keys.");
        this.state = 'WAITING_FOR_ACCEPT';
        this.isInitiator = true;
        this.tempKeyPair = await this._generateTempKeys();
        
        const rawPubKey = await window.crypto.subtle.exportKey("raw", this.tempKeyPair.publicKey);
        
        const offerPacket = {
            type: "HANDSHAKE_OFFER",
            payload: {
                pubKeyBase64: this._bufferToBase64(rawPubKey)
            }
        };
        
        this.ws.send(JSON.stringify(offerPacket));
    }

    /**
     * Encrypts and sends a plaintext message over the WebSocket.
     */
    async sendEncryptedMessage(plaintext) {
        if (this.state !== 'ESTABLISHED') throw new Error("Cannot send message: Handshake not established.");
        
        const { header, ciphertext } = await this.ratchet.encryptMessage(plaintext);
        
        const messagePacket = {
            type: "MESSAGE",
            payload: {
                dhPubKeyBase64: this._bufferToBase64(header.dhPubKey),
                ivBase64: this._bufferToBase64(header.iv),
                ciphertextBase64: this._bufferToBase64(ciphertext)
            }
        };
        
        this.ws.send(JSON.stringify(messagePacket));
    }

    /**
     * Core router for incoming JSON packets.
     */
    async handleIncomingMessage(messageData) {
        const packet = JSON.parse(messageData);

        if (packet.type === "HANDSHAKE_OFFER" && this.state === 'IDLE') {
            console.log("[Handshake] Received OFFER from peer.");
            await this._handleOffer(packet.payload);
            
        } else if (packet.type === "HANDSHAKE_ACCEPT" && this.state === 'WAITING_FOR_ACCEPT') {
            console.log("[Handshake] Received ACCEPT from peer.");
            await this._handleAccept(packet.payload);
            
        } else if (packet.type === "MESSAGE" && this.state === 'ESTABLISHED') {
            console.log("[Ratchet] Received Encrypted MESSAGE.");
            const plaintext = await this._handleEncryptedMessage(packet.payload);
            
            // Push the decrypted string up to the UI
            if (this.onMessageDecrypted) {
                this.onMessageDecrypted(plaintext);
            }
        }
        // Note: we ignore internal Daemon ACKs like {"status": "queued"} as the UI handles them directly.
    }

    async _handleOffer(payload) {
        const theirRawPubKey = this._base64ToBuffer(payload.pubKeyBase64);
        const theirImportedKey = await this._importPubKey(theirRawPubKey);

        this.tempKeyPair = await this._generateTempKeys();
        const sharedSecret = await this._deriveSecret(this.tempKeyPair.privateKey, theirImportedKey);

        const ourRawPubKey = await window.crypto.subtle.exportKey("raw", this.tempKeyPair.publicKey);
        
        this.theirRawPubKey = theirRawPubKey;
        this.ourRawPubKey = ourRawPubKey;
        this.isInitiator = false;

        const acceptPacket = {
            type: "HANDSHAKE_ACCEPT",
            payload: {
                pubKeyBase64: this._bufferToBase64(ourRawPubKey)
            }
        };
        this.ws.send(JSON.stringify(acceptPacket));

        // Bootstrap the Ratchet
        await this.ratchet.initializeSession(sharedSecret, this.tempKeyPair, theirImportedKey, false);
        this.state = 'ESTABLISHED';
        this.tempKeyPair = null; // clear temporary keys from memory
        console.log("[Handshake] Complete (Receiver Role). Double Ratchet is armed and ready.");

        if (this.onHandshakeEstablished) {
            this.onHandshakeEstablished();
        }
    }

    async _handleAccept(payload) {
        const theirRawPubKey = this._base64ToBuffer(payload.pubKeyBase64);
        const theirImportedKey = await this._importPubKey(theirRawPubKey);

        const sharedSecret = await this._deriveSecret(this.tempKeyPair.privateKey, theirImportedKey);

        const ourRawPubKey = await window.crypto.subtle.exportKey("raw", this.tempKeyPair.publicKey);
        this.ourRawPubKey = ourRawPubKey;
        this.theirRawPubKey = theirRawPubKey;

        // Bootstrap the Ratchet
        await this.ratchet.initializeSession(sharedSecret, this.tempKeyPair, theirImportedKey, true);
        this.state = 'ESTABLISHED';
        this.tempKeyPair = null; // clear temporary keys from memory
        console.log("[Handshake] Complete (Initiator Role). Double Ratchet is armed and ready.");

        if (this.onHandshakeEstablished) {
            this.onHandshakeEstablished();
        }
    }

    async _handleEncryptedMessage(payload) {
        const theirDhPubKeyRaw = this._base64ToBuffer(payload.dhPubKeyBase64);
        const iv = this._base64ToBuffer(payload.ivBase64);
        const ciphertext = this._base64ToBuffer(payload.ciphertextBase64);
        
        return await this.ratchet.decryptMessage(ciphertext, iv, theirDhPubKeyRaw);
    }

    /**
     * Generates an Out-of-Band Safety Number by hashing the combined public keys.
     * @returns {Promise<string>} The chunked safety number.
     */
    async generateSafetyNumber() {
        if (this.state !== 'ESTABLISHED') return null;

        // Ensure determinism: Initiator first, then Responder
        const initiatorKey = this.isInitiator ? this.ourRawPubKey : this.theirRawPubKey;
        const responderKey = this.isInitiator ? this.theirRawPubKey : this.ourRawPubKey;

        // Concatenate keys
        const combined = new Uint8Array(initiatorKey.byteLength + responderKey.byteLength);
        combined.set(new Uint8Array(initiatorKey), 0);
        combined.set(new Uint8Array(responderKey), initiatorKey.byteLength);

        // SHA-256 Hash
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', combined);
        const hashArray = new Uint8Array(hashBuffer);

        // Convert hash to a numeric string
        const hex = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
        let numStr = BigInt('0x' + hex).toString(10);

        // Pad to ensure at least 30 digits, then substring
        numStr = numStr.padStart(30, '0').substring(0, 30);

        // Chunk into groups of 5
        const chunks = [];
        for (let i = 0; i < numStr.length; i += 5) {
            chunks.push(numStr.substring(i, i + 5));
        }
        return chunks.join(' ');
    }

    // --- Cryptographic Primitives ---
    
    async _generateTempKeys() {
        return await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-384" },
            true,
            ["deriveBits"]
        );
    }

    async _importPubKey(rawBuffer) {
        return await window.crypto.subtle.importKey(
            "raw",
            rawBuffer,
            { name: "ECDH", namedCurve: "P-384" },
            true,
            []
        );
    }

    async _deriveSecret(privateKey, publicKey) {
        return await window.crypto.subtle.deriveBits(
            { name: "ECDH", public: publicKey },
            privateKey,
            384
        );
    }

    // --- Base64 / Binary Utilities ---

    _bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    _base64ToBuffer(base64) {
        const binaryString = window.atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
}
