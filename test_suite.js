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
    
    const aliceManager = new HandshakeManager(mockWsAlice, (msg) => { 
        console.log("Alice UI received decrypted message:", msg); 
    });
    const bobManager = new HandshakeManager(mockWsBob, (msg) => { 
        console.log("Bob UI received decrypted message:", msg); 
        bobDecryptedOutput = msg; 
    });
    
    // Trigger
    await aliceManager.initiateHandshake();
    
    // Wait for the async handshake messages to complete
    await new Promise(resolve => setTimeout(resolve, 100));
    
    assert(aliceManager.state === 'ESTABLISHED', "Alice HandshakeManager reached ESTABLISHED state.");
    assert(bobManager.state === 'ESTABLISHED', "Bob HandshakeManager reached ESTABLISHED state.");
    
    // =====================================================================
    // Test 3: End-to-End Simulation
    // =====================================================================
    console.log("\n--- Test 3: End-to-End Simulation ---");
    
    const testMsg = "Operation Midnight is a go.";
    await aliceManager.sendEncryptedMessage(testMsg);
    
    // Wait for the async MESSAGE delivery and decryption
    await new Promise(resolve => setTimeout(resolve, 100));
    
    assert(bobDecryptedOutput === testMsg, "Bob successfully intercepted, decrypted, and recovered the plaintext JSON message.");
    
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
