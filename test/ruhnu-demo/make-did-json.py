#!/usr/bin/env python3
"""Print a did:web DID document that lists ECDSA P-256 OpenSSH public keys under "authentication".

usage: make-did-json.py DID [PUBFILE ...] > did.json

Each key becomes a JsonWebKey2020 verification method with a P-256 publicKeyJwk, controller = DID.
With no PUBFILE the document lists no key (used by the demo to revoke access).
"""
import base64
import json
import struct
import sys


def read_string(buf, offset):
    (length,) = struct.unpack(">I", buf[offset:offset + 4])
    offset += 4
    return buf[offset:offset + length], offset + length


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_from_openssh_line(line):
    fields = line.split()
    blob = base64.b64decode(fields[1])
    key_type, offset = read_string(blob, 0)
    curve, offset = read_string(blob, offset)
    point, offset = read_string(blob, offset)
    if key_type != b"ecdsa-sha2-nistp256" or curve != b"nistp256" or len(point) != 65 or point[0] != 4:
        sys.exit("not an ecdsa-sha2-nistp256 key: " + fields[0])
    return {"kty": "EC", "crv": "P-256", "x": b64url(point[1:33]), "y": b64url(point[33:65])}


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    did = sys.argv[1]
    methods = []
    for i, path in enumerate(sys.argv[2:]):
        with open(path, encoding="ascii") as pub:
            methods.append({
                "id": did + "#key-" + str(i),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk_from_openssh_line(pub.read()),
            })
    document = {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
        "id": did,
        "verificationMethod": methods,
        "authentication": [m["id"] for m in methods],
    }
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
