// crypto_ratchet.js

export class DoubleRatchet {
    constructor() {
        this.rootKey = null; // ArrayBuffer
        this.sendChainKey = null; // ArrayBuffer
        this.recvChainKey = null; // ArrayBuffer

        this.ourKeyPair = null; // CryptoKeyPair
        this.theirPublicKey = null; // CryptoKey

        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
    }

    /**
     * Bootstraps the Double Ratchet state after the Initial Handshake.
     * @param {ArrayBuffer} sharedSecret 32-byte secret established via handshake
     * @param {CryptoKeyPair} ourHandshakePair The key pair generated during the handshake
     * @param {CryptoKey} theirHandshakePubKey The remote peer's public key from the handshake
     * @param {boolean} isInitiator True if we sent the HANDSHAKE_OFFER
     */
    async initializeSession(sharedSecret, ourHandshakePair, theirHandshakePubKey, isInitiator) {
        this.rootKey = sharedSecret;

        if (isInitiator) {
            // Initiator generates a NEW ephemeral key pair to start the sending chain
            this.ourKeyPair = await this.generateKeyPair();
            this.theirPublicKey = theirHandshakePubKey;

            // Perform the first DH step
            const dhSecret = await this.deriveSharedSecret(this.ourKeyPair.privateKey, this.theirPublicKey);
            const { newRootKey, newChainKey } = await this.kdfRoot(this.rootKey, dhSecret);

            this.rootKey = newRootKey;
            this.sendChainKey = newChainKey;
            this.recvChainKey = null;
        } else {
            // Responder uses their handshake key pair as their initial state
            this.ourKeyPair = ourHandshakePair;
            this.theirPublicKey = null; // Waiting for Initiator's first message

            this.sendChainKey = null;
            this.recvChainKey = null;
        }
    }

    /**
     * Integration API: Encrypt Message using AES-GCM
     * @param {string} plaintext The message to encrypt
     * @returns {Promise<Object>} An object containing the header (iv, dhPubKey) and ciphertext
     */
    async encryptMessage(plaintext) {
        if (!this.sendChainKey) throw new Error("Ratchet not initialized for sending.");

        // 1. Step the sending chain forward
        const { newChainKey, messageKey } = await this.kdfChain(this.sendChainKey);
        this.sendChainKey = newChainKey;

        // 2. Import the derived messageKey for AES-GCM
        const aesKey = await window.crypto.subtle.importKey(
            "raw",
            messageKey,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
        );

        // 3. Encrypt the plaintext with a random 12-byte IV
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedPlaintext = this.encoder.encode(plaintext);

        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            encodedPlaintext
        );

        // 4. Export our current public key to attach to the message header
        const exportedPubKey = await window.crypto.subtle.exportKey("raw", this.ourKeyPair.publicKey);

        return {
            header: {
                dhPubKey: exportedPubKey, // ArrayBuffer
                iv: iv.buffer             // ArrayBuffer
            },
            ciphertext: ciphertextBuffer  // ArrayBuffer
        };
    }

    /**
     * Integration API: Decrypt Message using AES-GCM
     * @param {ArrayBuffer} ciphertext The encrypted payload
     * @param {ArrayBuffer} iv The 12-byte initialization vector
     * @param {ArrayBuffer} theirDhPublicKeyRaw The peer's DH public key from the message header
     * @returns {Promise<string>} The decrypted plaintext string
     */
    async decryptMessage(ciphertext, iv, theirDhPublicKeyRaw) {
        // 1. Check if the peer sent a new DH public key (requires a Root step)
        let needsRootStep = true;
        let importedPubKey = null;

        if (this.theirPublicKey) {
            const currentRaw = await window.crypto.subtle.exportKey("raw", this.theirPublicKey);
            if (this._buffersEqual(currentRaw, theirDhPublicKeyRaw)) {
                needsRootStep = false;
            }
        }

        if (needsRootStep) {
            // Import their new public key
            importedPubKey = await window.crypto.subtle.importKey(
                "raw",
                theirDhPublicKeyRaw,
                { name: "ECDH", namedCurve: "P-384" },
                true,
                []
            );

            // Step 1 of Root Ratchet: Derive new DH shared secret using OUR current private key & THEIR new public key
            // Note: If this is the very first message we receive, we use the initial ourKeyPair we generated.
            const dhSecret = await this.deriveSharedSecret(this.ourKeyPair.privateKey, importedPubKey);

            // Step the root chain to establish our new receiving chain
            const { newRootKey, newChainKey: nextRecvChain } = await this.kdfRoot(this.rootKey, dhSecret);
            this.rootKey = newRootKey;
            this.recvChainKey = nextRecvChain;
            this.theirPublicKey = importedPubKey;

            // Step 2 of Root Ratchet: Generate a NEW key pair for OUR next sending chain step 
            this.ourKeyPair = await this.generateKeyPair();

            // Step the root ratchet again with OUR NEW private key and THEIR NEW public key
            // to derive the future sending chain.
            const nextDhSecret = await this.deriveSharedSecret(this.ourKeyPair.privateKey, this.theirPublicKey);
            const { newRootKey: nextRootKey, newChainKey: nextSendChain } = await this.kdfRoot(this.rootKey, nextDhSecret);

            this.rootKey = nextRootKey;
            this.sendChainKey = nextSendChain;
        }

        // 2. Step the receiving chain forward
        if (!this.recvChainKey) throw new Error("Ratchet not initialized for receiving. Did we miss a DH step?");
        const { newChainKey, messageKey } = await this.kdfChain(this.recvChainKey);
        this.recvChainKey = newChainKey;

        // 3. Import the derived messageKey for AES-GCM
        const aesKey = await window.crypto.subtle.importKey(
            "raw",
            messageKey,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        // 4. Decrypt the ciphertext
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: new Uint8Array(iv) },
            aesKey,
            ciphertext
        );

        return this.decoder.decode(decryptedBuffer);
    }

    // --- Core Crypto Primitives ---

    async generateKeyPair() {
        return await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-384" },
            true,
            ["deriveKey", "deriveBits"]
        );
    }

    async deriveSharedSecret(privateKey, publicKey) {
        return await window.crypto.subtle.deriveBits(
            { name: "ECDH", public: publicKey },
            privateKey,
            384
        );
    }

    async hkdf(ikmBuffer, saltBuffer, infoString, outputLength) {
        const ikmKey = await window.crypto.subtle.importKey(
            "raw",
            ikmBuffer,
            { name: "HKDF" },
            false,
            ["deriveBits"]
        );

        const derivedBits = await window.crypto.subtle.deriveBits(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: saltBuffer,
                info: this.encoder.encode(infoString)
            },
            ikmKey,
            outputLength * 8
        );

        return derivedBits;
    }

    async kdfChain(chainKeyBuffer) {
        const constantSalt = new Uint8Array(32).buffer;
        const derived = await this.hkdf(chainKeyBuffer, constantSalt, "KDF_CHAIN", 64);

        return {
            newChainKey: derived.slice(0, 32),
            messageKey: derived.slice(32, 64)
        };
    }

    async kdfRoot(rootKeyBuffer, dhSecretBuffer) {
        const derived = await this.hkdf(dhSecretBuffer, rootKeyBuffer, "ROOT_CHAIN", 64);

        return {
            newRootKey: derived.slice(0, 32),
            newChainKey: derived.slice(32, 64)
        };
    }

    // --- Utility ---

    _buffersEqual(buf1, buf2) {
        if (buf1.byteLength !== buf2.byteLength) return false;
        const dv1 = new Int8Array(buf1);
        const dv2 = new Int8Array(buf2);
        for (let i = 0; i !== buf1.byteLength; i++) {
            if (dv1[i] !== dv2[i]) return false;
        }
        return true;
    }
}