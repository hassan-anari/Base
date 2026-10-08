"""Isolated HTTPS transport. This does not enable the guarded MPC signing backend."""

import http.client
import json
import ssl
from urllib.parse import urlencode, urlsplit

import requests
from cryptography import x509
from django.conf import settings


def coordinator_request(method, path, *, json_payload=None, params=None):
    url = urlsplit(settings.MPC_COORDINATOR_URL)
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        raise ValueError("MPC coordinator requires an HTTPS service URL")
    if url.path not in ("", "/") or url.query or url.fragment:
        raise ValueError("MPC coordinator URL must not contain a path, query or fragment")
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("MPC request requires an absolute service path")
    context = ssl.create_default_context(cafile=settings.MPC_CA_CERT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(settings.MPC_CLIENT_CERT, settings.MPC_CLIENT_KEY)
    connection = http.client.HTTPSConnection(
        url.hostname,
        url.port or 443,
        context=context,
        timeout=settings.MPC_REQUEST_TIMEOUT_SECONDS,
    )
    try:
        connection.connect()  # CA, validity, server EKU and hostname verification first.
        certificate = x509.load_der_x509_certificate(connection.sock.getpeercert(binary_form=True))
        identities = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
        if identities != ["spiffe://wallet-mpc/coordinator"]:
            raise ssl.SSLCertVerificationError("unexpected coordinator certificate identity")
        if params:
            path += "?" + urlencode(params)
        body = None if json_payload is None else json.dumps(json_payload).encode()
        connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        if response.status == 404:
            from .signer_adapter import CoordinatorSessionNotFound

            raise CoordinatorSessionNotFound(path)
        if response.status != 200:
            # Redirects are rejected; certificates are never sent to a redirect target.
            raise requests.HTTPError(f"MPC coordinator HTTP {response.status}")
        data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("MPC response exceeds size limit")
        return json.loads(data)
    finally:
        connection.close()
