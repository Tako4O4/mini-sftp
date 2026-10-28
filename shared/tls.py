import ssl
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CERT_FILE = PROJECT_ROOT / "certs" / "server.crt"
KEY_FILE = PROJECT_ROOT / "certs" / "server.key"


def create_server_context(
    cert_file: Path = CERT_FILE,
    key_file: Path = KEY_FILE,
) -> ssl.SSLContext:
    """Create a TLS context for the server"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    return context


def create_client_context(cert_file: Path = CERT_FILE) -> ssl.SSLContext:
    """Create a client context that verifies the server"""
    context = ssl.create_default_context(cafile=str(cert_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
