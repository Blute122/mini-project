// test_suite.js
import { DoubleRatchet } from './crypto_ratchet.js';
import { HandshakeManager } from './handshake.js';

const assert = (condition, message) => {
    if (!condition) {
        throw new Error("Assertion failed: " + message);
    }
    console.log("✅ PASS: " + message);
    document.getElementById('output').innerHTML += `<br>✅ PASS: ${message}`;
};

const runTests = async () => {
    document.getElementById('output').innerHTML = "Starting Test Suite...<br>";
    console.log("Starting Test Suite...");

    // =====================================================================
    // Test 1: The Cryptographic Engine (DoubleRatchet)
    // =====================================================================
    console.log("\n--- Test 1: Cryptographic Engine ---");
    const aliceRatchet = new DoubleRatchet();
    const bobRatchet = new DoubleRatchet();

    // Generate handshake key pairs
    const aliceHandshakePair = await aliceRatchet.generateKeyPair();
    const bobHandshakePair = await bobRatchet.generateKeyPair();

    // Derive initial shared secret
    const sharedSecret = await aliceRatchet.deriveSharedSecret(aliceHandshakePair.privateKey, bobHandshakePair.publicKey);

    // Bootstrapping
    await aliceRatchet.initializeSession(sharedSecret, aliceHandshakePair, bobHandshakePair.publicKey, true);
    await bobRatchet.initializeSession(sharedSecret, bobHandshakePair, aliceHandshakePair.publicKey, false);

    // Encrypt
    const plaintext = "Target neutralized";
    const { header, ciphertext } = await aliceRatchet.encryptMessage(plaintext);

    // Decrypt
    const decryptedText = await bobRatchet.decryptMessage(ciphertext, header.iv, header.dhPubKey);

    assert(decryptedText === plaintext, "Bob successfully decrypted Alice's encrypted message exactly.");

    // =====================================================================
    // Test 2: The Handshake State Machine
    // =====================================================================
    console.log("\n--- Test 2: Handshake State Machine ---");

    let bobDecryptedOutput = null;

    // Mock WebSocket class to simulate network delivery without an actual server
    class MockWebSocket {
        constructor() {
            this.peer = null;
        }
        setPeer(peerWs) {
            this.peer = peerWs;
        }
        send(data) {
            // Forward output to peer asynchronously
            setTimeout(() => {
                if (this.peer && this.peer._onmessage) {
                    this.peer._onmessage({ data });
                }
            }, 10);
        }
        addEventListener(event, callback) {
            if (event === 'message') {
                this._onmessage = callback;
            }
        }
    }

    const mockWsAlice = new MockWebSocket();
    const mockWsBob = new MockWebSocket();
    mockWsAlice.setPeer(mockWsBob);
    mockWsBob.setPeer(mockWsAlice);

    const aliceIdentity = await window.crypto.subtle.generateKey(
        { name: "Ed25519" }, true, ["sign", "verify"]
    );
    const bobIdentity = await window.crypto.subtle.generateKey(
        { name: "Ed25519" }, true, ["sign", "verify"]
    );

    const aliceManager = new HandshakeManager(mockWsAlice, (msg) => {
        console.log("Alice UI received decrypted message:", msg);
    });
    const bobManager = new HandshakeManager(mockWsBob, (msg) => {
        console.log("Bob UI received decrypted message:", msg);
        bobDecryptedOutput = msg;
    });
    aliceManager.identityKeyPair = aliceIdentity;
    bobManager.identityKeyPair = bobIdentity;

    // Trigger
    await aliceManager.initiateHandshake();

    // Wait for the async handshake messages to complete
    await new Promise(resolve => setTimeout(resolve, 100));

    assert(aliceManager.state === 'ESTABLISHED', "Alice HandshakeManager reached ESTABLISHED state.");
    assert(bobManager.state === 'ESTABLISHED', "Bob HandshakeManager reached ESTABLISHED state.");
    assert(aliceManager.canSendEncrypted(), "Alice can send immediately after handshake.");
    assert(bobManager.canSendEncrypted(), "Bob can send immediately after handshake.");

    // =====================================================================
    // Test 3: End-to-End Simulation
    // =====================================================================
    console.log("\n--- Test 3: End-to-End Simulation ---");

    const testMsg = "Operation Midnight is a go.";
    await aliceManager.sendEncryptedMessage(testMsg);

    // Wait for the async MESSAGE delivery and decryption
    await new Promise(resolve => setTimeout(resolve, 100));

    assert(bobDecryptedOutput === testMsg, "Bob successfully intercepted, decrypted, and recovered the plaintext JSON message.");

    // =====================================================================
    // Test 4: Out-of-Band Authentication (Safety Numbers)
    // =====================================================================
    console.log("\n--- Test 4: Out-of-Band Authentication (Safety Numbers) ---");

    const mockWsAlice4 = new MockWebSocket();
    const mockWsBob4 = new MockWebSocket();
    mockWsAlice4.setPeer(mockWsBob4);
    mockWsBob4.setPeer(mockWsAlice4);

    const aliceIdentity4 = await window.crypto.subtle.generateKey(
        { name: "Ed25519" }, true, ["sign", "verify"]
    );
    const bobIdentity4 = await window.crypto.subtle.generateKey(
        { name: "Ed25519" }, true, ["sign", "verify"]
    );

    let aliceSafetyNumber = null;
    let bobSafetyNumber = null;

    const aliceManager4 = new HandshakeManager(mockWsAlice4, () => { }, async () => {
        aliceSafetyNumber = await aliceManager4.generateSafetyNumber();
    });
    const bobManager4 = new HandshakeManager(mockWsBob4, () => { }, async () => {
        bobSafetyNumber = await bobManager4.generateSafetyNumber();
    });
    aliceManager4.identityKeyPair = aliceIdentity4;
    bobManager4.identityKeyPair = bobIdentity4;

    await aliceManager4.initiateHandshake();

    // Wait for handshake and safety number generation
    await new Promise(resolve => setTimeout(resolve, 150));

    assert(aliceSafetyNumber !== null, "Alice successfully generated a Safety Number.");
    assert(bobSafetyNumber !== null, "Bob successfully generated a Safety Number.");
    assert(aliceSafetyNumber === bobSafetyNumber, "Alice and Bob generated strictly identical Safety Numbers.");

    console.log(`🔒 Verified Safety Number: ${aliceSafetyNumber}`);
    document.getElementById('output').innerHTML += `<br><span style='color:var(--accent);'>🔒 Safety Number Chunking Verified: ${aliceSafetyNumber}</span>`;

    console.log("\n🎉 ALL TESTS PASSED!");
    document.getElementById('output').innerHTML += "<br><br><span style='color:var(--success);font-weight:bold;'>🎉 ALL TESTS PASSED! System verified.</span>";
};

// Execute on DOM Load
window.addEventListener('DOMContentLoaded', () => {
    runTests().catch(e => {
        console.error("Test failed:", e);
        document.getElementById('output').innerHTML += `<br><br><span style='color:red;font-weight:bold;'>❌ ERROR: ${e.message}</span>`;
    });
});
