// handshake.js — with Ed25519 identity signatures on handshake packets

import { DoubleRatchet } from './crypto_ratchet.js';

export class HandshakeManager {
    constructor(websocket, onMessageDecrypted, onHandshakeEstablished, onBinaryReceived) {
        this.ws                     = websocket;
        this.onMessageDecrypted     = onMessageDecrypted;
        this.onHandshakeEstablished = onHandshakeEstablished;
        this.onBinaryReceived       = onBinaryReceived;
        this.ratchet                = new DoubleRatchet();
        this.state                  = 'IDLE';
        this.tempKeyPair            = null;
        this.ourRawPubKey           = null;
        this.theirRawPubKey         = null;
        this.isInitiator            = false;

        // Ed25519 identity keypair — set by index.html after key generation/restore
        this.identityKeyPair        = null;
        // Their verified Ed25519 public key — set after successful signature verify
        this.theirIdentityPubKey    = null;

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

    // ── Handshake ─────────────────────────────────────────────────────────────

    async initiateHandshake() {
        if (this.state !== 'IDLE') throw new Error("Handshake already in progress.");
        if (!this.identityKeyPair) throw new Error("Identity keypair not set.");

        this.state       = 'WAITING_FOR_ACCEPT';
        this.isInitiator = true;
        this.tempKeyPair = await this._generateTempKeys();

        const rawPubKey = await window.crypto.subtle.exportKey("raw", this.tempKeyPair.publicKey);

        // Sign the ECDH public key with our Ed25519 identity key.
        // This binds the handshake key to our identity — the receiver can verify
        // that whoever holds the Ed25519 private key deliberately chose this ECDH key.
        const signature = await this._signBytes(rawPubKey);

        // Export our Ed25519 public key so the receiver can verify
        const idPubKeySpki = await window.crypto.subtle.exportKey("spki", this.identityKeyPair.publicKey);

        const offerPacket = {
            type:     "HANDSHAKE_OFFER",
            senderId: this.clientId,
            payload: {
                pubKeyBase64:    this._bufferToBase64(rawPubKey),
                signatureBase64: this._bufferToBase64(signature),
                idPubKeyBase64:  this._bufferToBase64(idPubKeySpki)
            }
        };
        this.ws.send(JSON.stringify(offerPacket));
    }

    async sendEncryptedMessage(plaintext) {
        if (this.state !== 'ESTABLISHED') throw new Error("Not established.");
        const { header, ciphertext } = await this.ratchet.encryptMessage(plaintext);
        const messagePacket = {
            type:     "MESSAGE",
            senderId: this.clientId,
            payload: {
                dhPubKeyBase64:   this._bufferToBase64(header.dhPubKey),
                ivBase64:         this._bufferToBase64(header.iv),
                ciphertextBase64: this._bufferToBase64(ciphertext),
                msgIndex:         header.msgIndex   // sequence number for ordering/replay
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
            const plaintext = await this._handleEncryptedMessage(packet.payload);
            if (this.onMessageDecrypted) this.onMessageDecrypted(plaintext);
        }
    }

    async _handleOffer(payload) {
        // 1. Import their Ed25519 identity public key
        const idPubKeyRaw      = this._base64ToBuffer(payload.idPubKeyBase64);
        const theirIdentityKey = await window.crypto.subtle.importKey(
            "spki", idPubKeyRaw, { name: "Ed25519" }, true, ["verify"]
        );

        // 2. Verify their ECDH public key is signed by their identity key.
        //    If this fails, someone is tampering with the handshake.
        const theirRawPubKey = this._base64ToBuffer(payload.pubKeyBase64);
        const signature      = this._base64ToBuffer(payload.signatureBase64);
        const valid          = await window.crypto.subtle.verify(
            { name: "Ed25519" }, theirIdentityKey, signature, theirRawPubKey
        );
        if (!valid) throw new Error("HANDSHAKE_OFFER signature verification FAILED — possible MITM");

        this.theirIdentityPubKey = theirIdentityKey;

        // 3. Generate our ECDH keypair, derive shared secret
        const theirImportedKey = await this._importPubKey(theirRawPubKey);
        this.tempKeyPair       = await this._generateTempKeys();
        const sharedSecret     = await this._deriveSecret(this.tempKeyPair.privateKey, theirImportedKey);
        const ourRawPubKey     = await window.crypto.subtle.exportKey("raw", this.tempKeyPair.publicKey);

        this.theirRawPubKey = theirRawPubKey;
        this.ourRawPubKey   = ourRawPubKey;
        this.isInitiator    = false;

        // 4. Sign our ECDH public key with our identity key
        const ourSignature  = await this._signBytes(ourRawPubKey);
        const idPubKeySpki  = await window.crypto.subtle.exportKey("spki", this.identityKeyPair.publicKey);

        const acceptPacket = {
            type:     "HANDSHAKE_ACCEPT",
            senderId: this.clientId,
            payload: {
                pubKeyBase64:    this._bufferToBase64(ourRawPubKey),
                signatureBase64: this._bufferToBase64(ourSignature),
                idPubKeyBase64:  this._bufferToBase64(idPubKeySpki)
            }
        };
        this.ws.send(JSON.stringify(acceptPacket));

        await this.ratchet.initializeSession(sharedSecret, this.tempKeyPair, theirImportedKey, false);
        this.state       = 'ESTABLISHED';
        this.tempKeyPair = null;
        if (this.onHandshakeEstablished) this.onHandshakeEstablished();
    }

    async _handleAccept(payload) {
        // 1. Import their Ed25519 identity public key
        const idPubKeyRaw      = this._base64ToBuffer(payload.idPubKeyBase64);
        const theirIdentityKey = await window.crypto.subtle.importKey(
            "spki", idPubKeyRaw, { name: "Ed25519" }, true, ["verify"]
        );

        // 2. Verify their ECDH public key signature
        const theirRawPubKey = this._base64ToBuffer(payload.pubKeyBase64);
        const signature      = this._base64ToBuffer(payload.signatureBase64);
        const valid          = await window.crypto.subtle.verify(
            { name: "Ed25519" }, theirIdentityKey, signature, theirRawPubKey
        );
        if (!valid) throw new Error("HANDSHAKE_ACCEPT signature verification FAILED — possible MITM");

        this.theirIdentityPubKey = theirIdentityKey;

        // 3. Derive shared secret and complete ratchet setup
        const theirImportedKey = await this._importPubKey(theirRawPubKey);
        const sharedSecret     = await this._deriveSecret(this.tempKeyPair.privateKey, theirImportedKey);
        const ourRawPubKey     = await window.crypto.subtle.exportKey("raw", this.tempKeyPair.publicKey);

        this.ourRawPubKey   = ourRawPubKey;
        this.theirRawPubKey = theirRawPubKey;

        await this.ratchet.initializeSession(sharedSecret, this.tempKeyPair, theirImportedKey, true);
        this.state       = 'ESTABLISHED';
        this.tempKeyPair = null;
        if (this.onHandshakeEstablished) this.onHandshakeEstablished();
    }

    async _handleEncryptedMessage(payload) {
        const theirDhPubKeyRaw = this._base64ToBuffer(payload.dhPubKeyBase64);
        const iv               = this._base64ToBuffer(payload.ivBase64);
        const ciphertext       = this._base64ToBuffer(payload.ciphertextBase64);
        const msgIndex         = payload.msgIndex;   // may be undefined for legacy packets
        return await this.ratchet.decryptMessage(ciphertext, iv, theirDhPubKeyRaw, msgIndex);
    }

    // ── Safety Number ─────────────────────────────────────────────────────────
    // Now computed from Ed25519 identity keys rather than ephemeral ECDH keys.
    // This means the Safety Number is stable across sessions — if you verify it
    // once with a contact, you don't need to re-verify after every page reload
    // as long as both parties keep the same identity keypair (via localStorage).
    async generateSafetyNumber() {
        if (this.state !== 'ESTABLISHED') return null;
        if (!this.theirIdentityPubKey) return null;

        const ourSpki   = await window.crypto.subtle.exportKey("spki", this.identityKeyPair.publicKey);
        const theirSpki = await window.crypto.subtle.exportKey("spki", this.theirIdentityPubKey);

        const initiatorKey = this.isInitiator ? ourSpki   : theirSpki;
        const responderKey = this.isInitiator ? theirSpki : ourSpki;

        const combined = new Uint8Array(initiatorKey.byteLength + responderKey.byteLength);
        combined.set(new Uint8Array(initiatorKey), 0);
        combined.set(new Uint8Array(responderKey), initiatorKey.byteLength);

        const hashBuffer = await window.crypto.subtle.digest('SHA-256', combined);
        const hex        = Array.from(new Uint8Array(hashBuffer))
                               .map(b => b.toString(16).padStart(2, '0')).join('');
        let numStr       = BigInt('0x' + hex).toString(10).padStart(30, '0').substring(0, 30);
        const chunks     = [];
        for (let i = 0; i < numStr.length; i += 5) chunks.push(numStr.substring(i, i + 5));
        return chunks.join(' ');
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async _signBytes(buffer) {
        return await window.crypto.subtle.sign(
            { name: "Ed25519" }, this.identityKeyPair.privateKey, buffer
        );
    }

    async _generateTempKeys() {
        return await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-384" }, true, ["deriveBits"]
        );
    }
    async _importPubKey(rawBuffer) {
        return await window.crypto.subtle.importKey(
            "raw", rawBuffer, { name: "ECDH", namedCurve: "P-384" }, true, []
        );
    }
    async _deriveSecret(privateKey, publicKey) {
        return await window.crypto.subtle.deriveBits(
            { name: "ECDH", public: publicKey }, privateKey, 384
        );
    }
    _bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary  = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return window.btoa(binary);
    }
    _base64ToBuffer(base64) {
        const binaryString = window.atob(base64);
        const bytes        = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
        return bytes.buffer;
    }
}