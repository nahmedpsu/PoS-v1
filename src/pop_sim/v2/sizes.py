"""Standards-aligned size estimate of a secured CAM (review R18).

The simulator measures its own wire format (JSON body, hex certificates, a
full certificate on every message), which inflates absolute sizes and the
ratio between modes.  This module gives an explicit, assumption-labelled
estimate in the style of IEEE 1609.2 / ETSI TS 103 097 with COER encoding:

* ``CAM_PAYLOAD``: an ETSI CAM with basic and high-frequency containers;
* ``SIGNED_OVERHEAD``: Ieee1609Dot2Data / SignedData headers (protocol
  version, content type, hash id, header info with generation time and PSID);
* ``SIGNATURE``: ECDSA P-256 with an x-only r point, as encoded;
* ``CERTIFICATE``: an explicit authorization ticket with a compressed
  P-256 verification key and a validity period, as encoded;
* ``DIGEST``: the HashedId8 a message carries as signer instead of the
  certificate once neighbours have it.

The values are typical encoded sizes, not a byte-exact encoder; the point is
the relative cost of attaching one more certificate, and how certificate
caching (the signer is a digest except in ``full_cert_share`` of messages)
changes it.  Under ``rekey`` and ``window`` a message carries a second,
holder-bound certificate (or its digest) besides the pseudonym certificate.
"""

from __future__ import annotations

CAM_PAYLOAD = 50
SIGNED_OVERHEAD = 30
SIGNATURE = 67
CERTIFICATE = 130
DIGEST = 8

ASSUMPTIONS = {"cam_payload": CAM_PAYLOAD, "signed_overhead": SIGNED_OVERHEAD, "signature": SIGNATURE,
               "certificate": CERTIFICATE, "digest": DIGEST,
               "basis": "typical COER-encoded sizes for IEEE 1609.2 / ETSI TS 103 097 secured CAMs; not a byte-exact encoder"}


def cam_bytes(mode: str, full_cert_share: float = 1.0) -> float:
    """Expected bytes per secured CAM in ``mode``; ``full_cert_share`` is the
    share of messages that carry certificates in full (1.0: always; the
    rest carry digests)."""
    signer = full_cert_share * CERTIFICATE + (1 - full_cert_share) * DIGEST
    certs = 2 if mode in ("rekey", "window") else 1
    return CAM_PAYLOAD + SIGNED_OVERHEAD + SIGNATURE + certs * signer


def size_table(modes=("recycle", "fresh", "fresh_vgk", "rekey", "window"), shares=(1.0, 0.2, 0.1)) -> dict:
    """Bytes per CAM by mode and caching share, with the ratio to recycle."""
    out = {"assumptions": ASSUMPTIONS, "rows": []}
    for share in shares:
        base = cam_bytes("recycle", share)
        for m in modes:
            b = cam_bytes(m, share)
            out["rows"].append({"mode": m, "full_cert_share": share, "bytes_per_cam": b, "ratio_to_recycle": b / base})
    return out
