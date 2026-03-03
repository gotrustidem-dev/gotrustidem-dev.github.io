"""
Check FIDO metadata root certificates for low-S signature compliance.

In ECDSA, a signature (r, s) is valid, but so is (r, n-s) where n is the curve order.
To avoid signature malleability, the "low-S" convention requires s <= n/2.
If s > n/2, the signature has a "high-S" problem.

secp256r1 curve order:
  n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
  n/2 = 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8
"""

import base64
import json
import os
import glob
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, utils

# secp256r1 curve order
SECP256R1_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
SECP256R1_HALF_ORDER = SECP256R1_ORDER // 2

def decode_der_signature(sig_bytes):
    """Decode a DER-encoded ECDSA signature into (r, s)."""
    r, s = utils.decode_dss_signature(sig_bytes)
    return r, s

def check_certificate_low_s(cert_b64, label=""):
    """Check if a certificate's ECDSA signature uses low-S."""
    # Clean up base64 (remove whitespace/newlines)
    cert_b64_clean = cert_b64.replace('\n', '').replace('\r', '').replace(' ', '')
    cert_der = base64.b64decode(cert_b64_clean)
    cert = x509.load_der_x509_certificate(cert_der)

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    # Get the signature bytes
    sig_bytes = cert.signature

    # Check if it's an ECDSA signature
    sig_algo = cert.signature_algorithm_oid.dotted_string
    # 1.2.840.10045.4.3.2 = ecdsa-with-SHA256
    # 1.2.840.10045.4.3.3 = ecdsa-with-SHA384
    ecdsa_oids = ['1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.1']

    if sig_algo not in ecdsa_oids:
        print(f"  [{label}] Subject: {subject}")
        print(f"    Signature algorithm: {sig_algo} (not ECDSA, skipping)")
        print()
        return None

    r, s = decode_der_signature(sig_bytes)

    is_low_s = s <= SECP256R1_HALF_ORDER
    is_high_s = not is_low_s

    print(f"  [{label}]")
    print(f"    Subject: {subject}")
    print(f"    Issuer:  {issuer}")
    print(f"    Sig Algorithm: {sig_algo}")
    print(f"    r = 0x{r:064X}")
    print(f"    s = 0x{s:064X}")
    print(f"    n/2 = 0x{SECP256R1_HALF_ORDER:064X}")
    if is_high_s:
        corrected_s = SECP256R1_ORDER - s
        print(f"    ❌ HIGH-S detected! s > n/2")
        print(f"    Corrected s (n-s) = 0x{corrected_s:064X}")
    else:
        print(f"    ✅ LOW-S OK (s <= n/2)")
    print()

    return is_low_s

def main():
    metadata_dir = r"c:\Users\gotrustidem\Documents\git project\python-fido2-2.0.0\examples\metadata"

    json_files = glob.glob(os.path.join(metadata_dir, "*.json"))

    if not json_files:
        print(f"No JSON files found in {metadata_dir}")
        return

    total_certs = 0
    high_s_certs = 0
    low_s_certs = 0

    for json_file in sorted(json_files):
        filename = os.path.basename(json_file)
        print(f"=" * 80)
        print(f"File: {filename}")
        print(f"=" * 80)

        with open(json_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)

        root_certs = metadata.get("attestationRootCertificates", [])
        if not root_certs:
            print("  No attestationRootCertificates found.")
            print()
            continue

        for i, cert_b64 in enumerate(root_certs):
            total_certs += 1
            result = check_certificate_low_s(cert_b64, label=f"Cert #{i+1}")
            if result is None:
                pass  # non-ECDSA
            elif result:
                low_s_certs += 1
            else:
                high_s_certs += 1

    print("=" * 80)
    print(f"SUMMARY")
    print(f"=" * 80)
    print(f"  Total ECDSA certificates checked: {total_certs}")
    print(f"  ✅ Low-S (OK):     {low_s_certs}")
    print(f"  ❌ High-S (問題):  {high_s_certs}")

if __name__ == "__main__":
    main()
