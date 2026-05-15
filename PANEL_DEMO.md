# Rufrone Panel Demo

## What this demo shows

- Two independent peers
- End-to-end identity derivation from passphrases
- Authenticated handshake
- Double Ratchet encrypted messaging
- Encrypted file transfer
- Relay-style transport over padded UDP between two daemon instances

## Quick start

1. Run `.\start_demo_peers.ps1`
2. Open:
   - `http://localhost:8000/?ws=ws://localhost:8080&peer=Peer-A`
   - `http://localhost:8000/?ws=ws://localhost:8082&peer=Peer-B`
3. Derive identity on both peers using different passphrases.
4. Click `Initiate Handshake` on Peer A.
5. Show that Peer B receives and completes the secure channel.
6. Send a text message from each side.
7. Send a file and show decrypt + save on the receiver.

## What to say

- `Each browser window is attached to a different daemon instance, so these are treated as separate peers.`
- `The identities are deterministically derived from passphrases and represented as Ed25519-based peer identities.`
- `The handshake authenticates the ephemeral ECDH keys with the long-term identity keys.`
- `After handshake, application data is protected with the Double Ratchet and AES-256-GCM.`
- `Files are encrypted client-side before transport; the relay path only sees framed ciphertext and metadata envelopes.`
- `The daemon only routes framed packets and does not decrypt application content.`

## Security architecture preserved

- Ed25519 identity binding is still active.
- ECDH P-384 key exchange is still active.
- Double Ratchet message protection is still active.
- AES-256-GCM content encryption is still active.
- File encryption is still client-side and end-to-end.
- Safety-number style peer verification is still active.
- The relay daemon remains cryptographically blind to plaintext.

## Demo caveat

This local demo uses two independent daemons on one machine with UDP relay-style exchange over localhost. The production topology can point those daemons at AWS/GCP relay nodes by changing the env files.
