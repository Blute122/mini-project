import { DoubleRatchet } from './crypto_ratchet.js';

export class HandshakeManager {
    constructor(websocket, onMessageDecrypted, onHandshakeEstablished, onBinaryReceived) {
        this.ws = websocket;
        this.onMessageDecrypted = onMessageDecrypted;
        this.onHandshakeEstablished = onHandshakeEstablished;
        this.onBinaryReceived = onBinaryReceived;
        this.ratchet = new DoubleRatchet();
        this.state = 'IDLE';
        this.tempKeyPair = null;
        this.ourRawPubKey = null;
        this.theirRawPubKey = null;
        this.isInitiator = false;

        this.clientId = Math.random().toString(36).substring(2, 15);
        this.ws.binaryType = "arraybuffer";

        this.ws.addEventListener('message', async (event) => {
            try {
                if (event.data instanceof ArrayBuffer || event.data instanceof Blob) {
                    let buffer = event.data;
                    if (event.data instanceof Blob) buffer = await event.data.arrayBuffer();
                    if (this.onBinaryReceived) this.onBinaryReceived(buffer);
                    return;
                }
                if (typeof event.data !== 'string' || !event.data.startsWith('{')) return;
                await this.handleIncomingMessage(event.data);
            } catch (e) {
                console.error("[HandshakeManager] Error:", e);
            }
        });
    }

    async initiateHandshake() {
        if (this.state !== 'IDLE') throw new Error("Handshake already in progress.");
        this.state = 'WAITING_FOR_ACCEPT';
        this.isInitiator = true;
        this.tempKeyPair = await this._generateTempKeys();
        const rawPubKey = await window.crypto.subtle.exportKey("raw", this.tempKeyPair.publicKey);
        const offerPacket = {
            type: "HANDSHAKE_OFFER",
            senderId: this.clientId,
            payload: { pubKeyBase64: this._bufferToBase64(rawPubKey) }
        };
        this.ws.send(JSON.stringify(offerPacket));
    }

    // Encrypts any plaintext string through the Double Ratchet and sends it
    // as a MESSAGE packet.  Used for both chat messages and file metadata —
    // the receiver decrypts and routes based on the plaintext content prefix.
    async sendEncryptedMessage(plaintext) {
        if (this.state !== 'ESTABLISHED') throw new Error("Not established.");
        const { header, ciphertext } = await this.ratchet.encryptMessage(plaintext);
        const messagePacket = {
            type: "MESSAGE",
            senderId: this.clientId,
            payload: {
                dhPubKeyBase64: this._bufferToBase64(header.dhPubKey),
                ivBase64: this._bufferToBase64(header.iv),
                ciphertextBase64: this._bufferToBase64(ciphertext)
            }
        };
        this.ws.send(JSON.stringify(messagePacket));
    }

    async handleIncomingMessage(messageData) {
        const packet = JSON.parse(messageData);
        if (packet.senderId === this.clientId) return;

        if (packet.type === "HANDSHAKE_OFFER" && this.state === 'IDLE') {
            await this._handleOffer(packet.payload);
        } else if (packet.type === "HANDSHAKE_ACCEPT" && this.state === 'WAITING_FOR_ACCEPT') {
            await this._handleAccept(packet.payload);
        } else if (packet.type === "MESSAGE" && this.state === 'ESTABLISHED') {
            // All application messages — chat AND file metadata — are now
            // Double-Ratchet encrypted MESSAGE packets.  The plaintext content
            // determines routing: the [FILE_META]::: prefix is checked in
            // index.html's onMessageDecrypted callback, not here.
            // The old FILE_TRANSFER_INIT special case has been removed because
            // it bypassed encryption entirely — filename, size, and the AES-GCM
            // file key were all visible in plaintext to anyone reading the
            // WebSocket stream.
            const plaintext = await this._handleEncryptedMessage(packet.payload);
            if (this.onMessageDecrypted) this.onMessageDecrypted(plaintext);
        }
        // FILE_TRANSFER_INIT case intentionally removed — file metadata now
        // travels as an encrypted MESSAGE (see sendFileMetaEncrypted in index.html)
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
            senderId: this.clientId,
            payload: { pubKeyBase64: this._bufferToBase64(ourRawPubKey) }
        };
        this.ws.send(JSON.stringify(acceptPacket));
        await this.ratchet.initializeSession(sharedSecret, this.tempKeyPair, theirImportedKey, false);
        this.state = 'ESTABLISHED';
        this.tempKeyPair = null;
        if (this.onHandshakeEstablished) this.onHandshakeEstablished();
    }

    async _handleAccept(payload) {
        const theirRawPubKey = this._base64ToBuffer(payload.pubKeyBase64);
        const theirImportedKey = await this._importPubKey(theirRawPubKey);
        const sharedSecret = await this._deriveSecret(this.tempKeyPair.privateKey, theirImportedKey);
        const ourRawPubKey = await window.crypto.subtle.exportKey("raw", this.tempKeyPair.publicKey);
        this.ourRawPubKey = ourRawPubKey;
        this.theirRawPubKey = theirRawPubKey;
        await this.ratchet.initializeSession(sharedSecret, this.tempKeyPair, theirImportedKey, true);
        this.state = 'ESTABLISHED';
        this.tempKeyPair = null;
        if (this.onHandshakeEstablished) this.onHandshakeEstablished();
    }

    async _handleEncryptedMessage(payload) {
        const theirDhPubKeyRaw = this._base64ToBuffer(payload.dhPubKeyBase64);
        const iv = this._base64ToBuffer(payload.ivBase64);
        const ciphertext = this._base64ToBuffer(payload.ciphertextBase64);
        return await this.ratchet.decryptMessage(ciphertext, iv, theirDhPubKeyRaw);
    }

    async generateSafetyNumber() {
        if (this.state !== 'ESTABLISHED') return null;
        const initiatorKey = this.isInitiator ? this.ourRawPubKey : this.theirRawPubKey;
        const responderKey = this.isInitiator ? this.theirRawPubKey : this.ourRawPubKey;
        const combined = new Uint8Array(initiatorKey.byteLength + responderKey.byteLength);
        combined.set(new Uint8Array(initiatorKey), 0);
        combined.set(new Uint8Array(responderKey), initiatorKey.byteLength);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', combined);
        const hashArray = new Uint8Array(hashBuffer);
        const hex = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
        let numStr = BigInt('0x' + hex).toString(10).padStart(30, '0').substring(0, 30);
        const chunks = [];
        for (let i = 0; i < numStr.length; i += 5) chunks.push(numStr.substring(i, i + 5));
        return chunks.join(' ');
    }

    async _generateTempKeys() {
        return await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, true, ["deriveBits"]);
    }
    async _importPubKey(rawBuffer) {
        return await window.crypto.subtle.importKey("raw", rawBuffer, { name: "ECDH", namedCurve: "P-384" }, true, []);
    }
    async _deriveSecret(privateKey, publicKey) {
        return await window.crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 384);
    }
    _bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return window.btoa(binary);
    }
    _base64ToBuffer(base64) {
        const binaryString = window.atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
        return bytes.buffer;
    }
}