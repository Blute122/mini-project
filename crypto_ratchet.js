// crypto_ratchet.js — Double Ratchet with message ordering + replay protection

export class DoubleRatchet {
    constructor() {
        this.rootKey = null;
        this.sendChainKey = null;
        this.recvChainKey = null;
        this.ourKeyPair = null;
        this.theirPublicKey = null;

        // Message ordering & replay protection
        this.sendCounter = 0;          // increments with every sent message
        this.recvCounter = 0;          // highest contiguous received index
        this.skippedKeys = new Map();  // Map<msgIndex, messageKey ArrayBuffer>
        // Maximum number of skipped keys we'll store (prevents unbounded memory)
        this.MAX_SKIP = 100;

        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
    }

    async initializeSession(sharedSecret, ourHandshakePair, theirHandshakePubKey, isInitiator) {
        this.rootKey = sharedSecret;

        if (isInitiator) {
            this.ourKeyPair = await this.generateKeyPair();
            this.theirPublicKey = theirHandshakePubKey;
            const dhSecret = await this.deriveSharedSecret(this.ourKeyPair.privateKey, this.theirPublicKey);
            const { newRootKey, newChainKey } = await this.kdfRoot(this.rootKey, dhSecret);
            this.rootKey = newRootKey;
            this.sendChainKey = newChainKey;
            this.recvChainKey = null;
        } else {
            this.ourKeyPair = ourHandshakePair;
            this.theirPublicKey = null;
            this.sendChainKey = null;
            this.recvChainKey = null;
        }

        this.sendCounter = 0;
        this.recvCounter = 0;
        this.skippedKeys.clear();
    }

    // ── Encrypt ──────────────────────────────────────────────────────────────
    async encryptMessage(plaintext) {
        if (!this.sendChainKey) throw new Error("Ratchet not initialized for sending.");

        const msgIndex = this.sendCounter++;

        const { newChainKey, messageKey } = await this.kdfChain(this.sendChainKey);
        this.sendChainKey = newChainKey;

        // Use msgIndex as Additional Authenticated Data so AES-GCM also
        // authenticates the sequence number — tampering with the index in
        // transit causes decryption to fail.
        const aad = this._indexToBytes(msgIndex);

        const aesKey = await window.crypto.subtle.importKey(
            "raw", messageKey, { name: "AES-GCM" }, false, ["encrypt"]
        );
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: aad },
            aesKey,
            this.encoder.encode(plaintext)
        );

        const exportedPubKey = await window.crypto.subtle.exportKey("raw", this.ourKeyPair.publicKey);

        return {
            header: {
                dhPubKey: exportedPubKey,
                iv: iv.buffer,
                msgIndex              // included in header so receiver knows sequence position
            },
            ciphertext: ciphertextBuffer
        };
    }

    // ── Decrypt ──────────────────────────────────────────────────────────────
    async decryptMessage(ciphertext, iv, theirDhPublicKeyRaw, msgIndex) {
        // Replay check — reject anything at or below the last contiguous index
        // unless we have it stored as a skipped key (out-of-order delivery).
        if (msgIndex !== undefined && msgIndex < this.recvCounter) {
            if (!this.skippedKeys.has(msgIndex)) {
                throw new Error(`Replay attack detected: msgIndex ${msgIndex} already processed`);
            }
        }

        let needsRootStep = true;
        if (this.theirPublicKey) {
            const currentRaw = await window.crypto.subtle.exportKey("raw", this.theirPublicKey);
            if (this._buffersEqual(currentRaw, theirDhPublicKeyRaw)) needsRootStep = false;
        }

        if (needsRootStep) {
            const importedPubKey = await window.crypto.subtle.importKey(
                "raw", theirDhPublicKeyRaw, { name: "ECDH", namedCurve: "P-384" }, true, []
            );
            const dhSecret = await this.deriveSharedSecret(this.ourKeyPair.privateKey, importedPubKey);
            const { newRootKey, newChainKey: nextRecvChain } = await this.kdfRoot(this.rootKey, dhSecret);
            this.rootKey = newRootKey;
            this.recvChainKey = nextRecvChain;
            this.theirPublicKey = importedPubKey;

            this.ourKeyPair = await this.generateKeyPair();
            const nextDhSecret = await this.deriveSharedSecret(this.ourKeyPair.privateKey, this.theirPublicKey);
            const { newRootKey: nextRootKey, newChainKey: nextSendChain } = await this.kdfRoot(this.rootKey, nextDhSecret);
            this.rootKey = nextRootKey;
            this.sendChainKey = nextSendChain;
        }

        if (!this.recvChainKey) throw new Error("Ratchet not initialized for receiving.");

        // If this message arrived out of order, its key was stored earlier
        let messageKey;
        if (msgIndex !== undefined && this.skippedKeys.has(msgIndex)) {
            messageKey = this.skippedKeys.get(msgIndex);
            this.skippedKeys.delete(msgIndex);
        } else {
            // Advance chain, storing skipped keys for any gaps
            if (msgIndex !== undefined) {
                await this._storeSkippedKeys(msgIndex);
            }
            const derived = await this.kdfChain(this.recvChainKey);
            this.recvChainKey = derived.newChainKey;
            messageKey = derived.messageKey;

            if (msgIndex !== undefined) {
                this.recvCounter = msgIndex + 1;
            }
        }

        const aad = msgIndex !== undefined ? this._indexToBytes(msgIndex) : new Uint8Array(4);

        const aesKey = await window.crypto.subtle.importKey(
            "raw", messageKey, { name: "AES-GCM" }, false, ["decrypt"]
        );

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: new Uint8Array(iv), additionalData: aad },
            aesKey,
            ciphertext
        );

        return this.decoder.decode(decryptedBuffer);
    }

    // Store message keys for messages we haven't received yet (gaps in sequence)
    async _storeSkippedKeys(targetIndex) {
        let skipped = targetIndex - this.recvCounter;
        if (skipped < 0) return;
        if (skipped > this.MAX_SKIP) throw new Error("Too many skipped messages — possible attack");

        for (let i = this.recvCounter; i < targetIndex; i++) {
            const { newChainKey, messageKey } = await this.kdfChain(this.recvChainKey);
            this.recvChainKey = newChainKey;
            this.skippedKeys.set(i, messageKey);
        }
    }

    _indexToBytes(index) {
        const buf = new ArrayBuffer(4);
        new DataView(buf).setUint32(0, index, false); // big-endian
        return new Uint8Array(buf);
    }

    // ── Core Crypto Primitives (unchanged) ───────────────────────────────────

    async generateKeyPair() {
        return await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-384" }, true, ["deriveKey", "deriveBits"]
        );
    }

    async deriveSharedSecret(privateKey, publicKey) {
        return await window.crypto.subtle.deriveBits(
            { name: "ECDH", public: publicKey }, privateKey, 384
        );
    }

    async hkdf(ikmBuffer, saltBuffer, infoString, outputLength) {
        const ikmKey = await window.crypto.subtle.importKey(
            "raw", ikmBuffer, { name: "HKDF" }, false, ["deriveBits"]
        );
        return await window.crypto.subtle.deriveBits(
            { name: "HKDF", hash: "SHA-256", salt: saltBuffer, info: this.encoder.encode(infoString) },
            ikmKey, outputLength * 8
        );
    }

    async kdfChain(chainKeyBuffer) {
        const constantSalt = new Uint8Array(32).buffer;
        const derived = await this.hkdf(chainKeyBuffer, constantSalt, "KDF_CHAIN", 64);
        return { newChainKey: derived.slice(0, 32), messageKey: derived.slice(32, 64) };
    }

    async kdfRoot(rootKeyBuffer, dhSecretBuffer) {
        const derived = await this.hkdf(dhSecretBuffer, rootKeyBuffer, "ROOT_CHAIN", 64);
        return { newRootKey: derived.slice(0, 32), newChainKey: derived.slice(32, 64) };
    }

    _buffersEqual(buf1, buf2) {
        if (buf1.byteLength !== buf2.byteLength) return false;
        const a = new Int8Array(buf1), b = new Int8Array(buf2);
        for (let i = 0; i < buf1.byteLength; i++) if (a[i] !== b[i]) return false;
        return true;
    }
}