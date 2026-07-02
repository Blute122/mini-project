# Panel Attacker Demo

## Goal

Show that a transport-path observer can capture traffic but cannot read:

- the plaintext chat message
- the plaintext file contents
- the file name in plaintext

## Best setup on this machine

Use the working two-peer local demo:

- Peer A daemon on `localhost:8080`, UDP `9001`
- Peer B daemon on `localhost:8082`, UDP `9002`
- Static UI on `localhost:8000`

## Windows capture tool

Primary on this machine: built-in passive relay-view capture.

This is stronger for the demo than `PktMon` on loopback because it records the exact ciphertext datagrams the blind transport layer forwards, including file traffic.

If Wireshark is already installed, you may still use it as a visual supplement.

## Demo payloads

Send this exact chat message:

`ATTACKER_SHOULD_NOT_SEE_THIS_123`

Send this exact file:

`TOP_SECRET_PANEL_FILE.txt`

The file contents already include a second known plaintext string:

`Rufrone panel demo confidential file payload`

## Commands

Run attacker capture in a PowerShell:

```powershell
.\start_attacker_capture.ps1
```

After sending the message and file, stop and analyze:

```powershell
.\stop_attacker_capture.ps1
```

## What to say live

Before sending:

- `We are now simulating an attacker at the relay or transport path.`
- `The attacker can observe and capture packets, but does not hold endpoint decryption keys.`
- `We will send a message and a file with known plaintext markers and then search the captured ciphertext stream for those markers.`

While sending:

- `This message contains a clear marker: ATTACKER_SHOULD_NOT_SEE_THIS_123.`
- `This file is named TOP_SECRET_PANEL_FILE.txt and contains another known plaintext marker.`

After capture analysis:

- `The receiver successfully recovered the message and file.`
- `The attacker captured the relay-path traffic, but searching that captured ciphertext stream does not reveal the plaintext markers.`
- `This demonstrates endpoint confidentiality against a transport-path observer.`

## What this proves

- An observer can see that traffic exists.
- An observer can capture packets.
- An observer cannot trivially recover the chat plaintext.
- An observer cannot trivially recover the file plaintext.
- The relay/transport path is not the holder of application plaintext.

## What not to overclaim

Do not say:

- `No attacker can get anything.`
- `We hide all metadata perfectly.`
- `This protects against a fully compromised endpoint.`

Say instead:

- `This demonstrates confidentiality against a passive transport-path observer.`
- `It also reduces metadata leakage, but does not claim perfect invisibility.`

## Optional Wireshark supplement

If Wireshark is available, use it only as a visual companion:

1. Capture loopback/local UDP traffic for ports `9001` and `9002`.
2. Show that packets and packet volume are visible.
3. Use the built-in passive relay-view capture for the actual plaintext-marker proof.
