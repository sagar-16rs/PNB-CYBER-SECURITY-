import ssl
import socket
import ipaddress
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse
import urllib.request

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import ExtensionOID


# ----------------------------
# CONSTANTS
# ----------------------------
COMMON_TLS_PORTS = [443, 8443, 9443]
VPN_PORTS = [1194, 443]

COMMON_SUBDOMAINS = [
    "api", "dev", "test", "portal", "login", "gateway"
]


# ----------------------------
# NORMALIZE TARGET
# ----------------------------
def normalize_target(target):
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    return parsed.hostname, parsed.port if parsed.port else 443


# ----------------------------
# CIDR EXPANSION
# ----------------------------
def expand_cidr(target):
    try:
        return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
    except:
        return [target]


# ----------------------------
# SUBDOMAIN DISCOVERY
# ----------------------------
def discover_subdomains(domain):
    found = []
    for sub in COMMON_SUBDOMAINS:
        candidate = f"{sub}.{domain}"
        try:
            socket.gethostbyname(candidate)
            found.append(candidate)
        except:
            pass
    return found


# ----------------------------
# PORT SCANNING
# ----------------------------
def scan_ports(host):
    open_ports = []
    for port in COMMON_TLS_PORTS + VPN_PORTS:
        try:
            with socket.create_connection((host, port), timeout=2):
                open_ports.append(port)
        except:
            pass
    return open_ports


def detect_vpn_ports(open_ports):
    return any(p in VPN_PORTS for p in open_ports)


def detect_api(endpoint):
    return any(p in endpoint.lower() for p in ["/api", "/v1", "/v2", "/graphql"])


# ----------------------------
# SECURITY DETECTION
# ----------------------------
def detect_cipher_strength(cipher):
    cipher = cipher.upper()
    if "CHACHA20" in cipher or "GCM" in cipher:
        return "strong"
    if "CBC" in cipher:
        return "medium"
    if any(w in cipher for w in ["RC4", "DES", "3DES"]):
        return "weak"
    return "unknown"


def detect_forward_secrecy(cipher):
    return any(k in cipher for k in ["ECDHE", "DHE"])


def detect_vulnerabilities(protocol, cipher):
    vulns = []
    if protocol == "SSLv3":
        vulns.append("POODLE")
    if protocol == "TLSv1":
        vulns.append("BEAST")
    if "RC4" in cipher:
        vulns.append("RC4 Bias")
    return vulns


def check_hsts(hostname):
    try:
        req = urllib.request.Request(f"https://{hostname}", method="HEAD")
        with urllib.request.urlopen(req, timeout=3) as response:
            return "strict-transport-security" in response.headers
    except:
        return False


# ----------------------------
# SCAN TARGET
# ----------------------------
def scan_single_target(target, port=443):

    hostname, _ = normalize_target(target)

    result = {
        "endpoint": f"{hostname}:{port}" if port != 443 else hostname,
        "status": "Failed",
        "protocol": None,
        "cipher": None,
        "alpn": None,
        "hsts_enabled": False,
        "open_ports": [],
        "vpn_detected": False,
        "is_api": detect_api(target),
        "certificate": {},
        "error": None
    }

    try:
        result["open_ports"] = scan_ports(hostname)
        result["vpn_detected"] = detect_vpn_ports(result["open_ports"])

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(['h2', 'http/1.1'])

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                cipher_tuple = ssock.cipher()
                if cipher_tuple:
                    result["cipher"] = cipher_tuple[0]
                    result["protocol"] = cipher_tuple[1]

                result["alpn"] = ssock.selected_alpn_protocol()

                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                public_key = cert.public_key()

                key_algo = "Unknown"
                key_size = getattr(public_key, "key_size", 0)

                if isinstance(public_key, rsa.RSAPublicKey):
                    key_algo = "RSA"
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_algo = "ECC"
                elif isinstance(public_key, dsa.DSAPublicKey):
                    key_algo = "DSA"

                sans = []
                try:
                    ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = ext.value.get_values_for_type(x509.DNSName)
                except:
                    pass

                result["certificate"] = {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "valid_from": cert.not_valid_before_utc.isoformat(),
                    "valid_until": cert.not_valid_after_utc.isoformat(),
                    "key_algorithm": key_algo,
                    "key_size": key_size,
                    "sans": sans[:5]
                }

                result["status"] = "Success"

        if port == 443:
            result["hsts_enabled"] = check_hsts(hostname)

    except Exception as e:
        result["error"] = str(e)

    return apply_scoring_models(result)


# ----------------------------
# DUAL SCORING SYSTEM
# ----------------------------
def apply_scoring_models(scan):

    if scan["status"] != "Success":
        return scan

    cipher = scan["cipher"].upper()
    protocol = scan["protocol"]
    cert = scan["certificate"]
    key_algo = cert["key_algorithm"]
    key_size = cert["key_size"]

    # ---------------- NORMAL SCORE (0–100)
    score = 50
    recommendations = []
    vulnerabilities = detect_vulnerabilities(protocol, cipher)

    if protocol == "TLSv1.3":
        score += 15
    elif protocol == "TLSv1.2":
        score += 8
    else:
        score -= 20

    strength = detect_cipher_strength(cipher)
    if strength == "strong":
        score += 15
    elif strength == "medium":
        score += 5
    else:
        score -= 20

    if detect_forward_secrecy(cipher):
        score += 10
    else:
        score -= 10

    if key_algo == "RSA":
        if key_size < 2048:
            score -= 20
        elif key_size >= 4096:
            score += 10

    if key_algo == "ECC":
        score += 10

    pqc_ready = any(p in cipher for p in ["KYBER", "ML-KEM", "DILITHIUM"])

    score = max(0, min(score, 100))

    tier = "Elite" if score >= 85 else "Standard" if score >= 60 else "Weak"

    # ---------------- QVI SCORE (0–1000)
    qvi_score = 100

    if pqc_ready:
        qvi_score += 200
    elif key_algo == "RSA":
        if key_size < 2048:
            qvi_score -= 50
        elif key_size < 3072:
            qvi_score -= 20

    if protocol in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
        qvi_score -= 40

    if not detect_forward_secrecy(cipher):
        qvi_score -= 20

    if not scan.get("hsts_enabled"):
        qvi_score -= 10

    qvi_score = int(max(0, min(qvi_score, 150)) * (1000 / 150))

    if pqc_ready:
        grade = "A+"
    elif qvi_score >= 900:
        grade = "A"
    elif qvi_score >= 750:
        grade = "B"
    elif qvi_score >= 500:
        grade = "C"
    else:
        grade = "F"

    return {
        **scan,
        "score": score,
        "tier": tier,
        "qvi_score": qvi_score,
        "grade": grade,
        "pqc_label": "Fully Quantum Safe" if pqc_ready else "Not PQC Ready",
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations
    }


# ----------------------------
# ENTERPRISE SCORE
# ----------------------------
def enterprise_score(results):
    scores = [r.get("qvi_score", 0) for r in results if r.get("status") == "Success"]
    return int(sum(scores) / len(scores)) if scores else 0


# ----------------------------
# BULK SCAN
# ----------------------------
def bulk_scan(targets, deep_scan=False):

    expanded = []

    for t in targets:
        expanded.extend(expand_cidr(t))
        if deep_scan:
            expanded.extend(discover_subdomains(t))

    expanded = list(set(expanded))

    ports = COMMON_TLS_PORTS if deep_scan else [443]

    tasks = [(t, p) for t in expanded for p in ports]

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_single_target, t, p) for t, p in tasks]

        for f in concurrent.futures.as_completed(futures):
            try:
                results.append(f.result())
            except:
                pass

    return results