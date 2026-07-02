import argparse
import base64
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Analyze Rufrone transport capture for plaintext leakage.")
    parser.add_argument("--log", default="attack_capture.ndjson")
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        raise SystemExit(f"Capture log not found: {log_path}")

    patterns = [
        b"ATTACKER_SHOULD_NOT_SEE_THIS_123",
        b"TOP_SECRET_PANEL_FILE",
        b"Rufrone panel demo confidential file payload",
    ]

    packet_count = 0
    total_bytes = 0
    frame_counts = {}
    direction_counts = {}
    combined = bytearray()

    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            payload = base64.b64decode(entry["b64"])
            packet_count += 1
            total_bytes += len(payload)
            frame_type = entry.get("frame_type", "")
            direction = entry.get("dir", "unknown")
            frame_counts[frame_type] = frame_counts.get(frame_type, 0) + 1
            direction_counts[direction] = direction_counts.get(direction, 0) + 1
            combined.extend(payload)

    print(f"Capture file: {log_path}")
    print(f"Packets logged: {packet_count}")
    print(f"Bytes logged: {total_bytes}")
    print(f"Directions: {json.dumps(direction_counts, sort_keys=True)}")
    print(f"Frame types: {json.dumps(frame_counts, sort_keys=True)}")
    print("")

    leaks = []
    for pattern in patterns:
        offset = bytes(combined).find(pattern)
        if offset >= 0:
            leaks.append((pattern.decode("utf-8", "ignore"), offset))

    if leaks:
        print("WARNING: plaintext markers found in captured transport stream")
        for marker, offset in leaks:
            print(f"  FOUND: {marker} @ offset {offset}")
    else:
        print("PASS: plaintext markers were NOT found in captured transport stream")


if __name__ == "__main__":
    main()
