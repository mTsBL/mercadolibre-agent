"""Deterministic evidence gates. The model cannot manufacture a finding."""

import hashlib
import json
import re

from .safety import CPF_PATTERN, fingerprint
from .transport import Response


CPF_CONTEXT = re.compile(r"\bcpf\b|cadastro\s+de\s+pessoas\s+f[ií]sicas|tax[_\s-]?(?:id|number)|document[_\s-]?(?:number|id)", re.I)
ERROR_CONTEXT = re.compile(r"\b(error|unauthorized|forbidden|access denied|not found|invalid|denied|erro|negado)\b", re.I)


def valid_cpf(value: str) -> bool:
    digits = re.sub(r"[^0-9]", "", value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for size in (9, 10):
        remainder = sum(int(digits[i]) * (size + 1 - i) for i in range(size)) * 10 % 11
        if int(digits[size]) != (0 if remainder == 10 else remainder):
            return False
    return True


def cpf_matches(response):
    if not response.textual or response.status >= 400:
        return []
    # Code, CSS and source maps often contain validation examples, not application data.
    ctype = response.headers.get("content-type", "").lower()
    if any(t in ctype for t in ("javascript", "css")) or response.url.endswith((".js", ".mjs", ".map")):
        return []
    text = response.text
    if "html" in ctype:
        text = re.sub(r"<(script|style)\b[^>]*>.*?</\1\s*>", "", text, flags=re.I | re.S)
        text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    matches = []
    for match in CPF_PATTERN.finditer(text):
        context = text[max(0, match.start() - 100):match.end() + 50]
        if valid_cpf(match[0]) and CPF_CONTEXT.search(context):
            matches.append({"digits": re.sub(r"\D", "", match[0]), "offset": match.start()})
    return matches


def useful(response):
    if response.truncated or response.status != 200 or not response.textual or len(response.body) < 5:
        return False
    ctype = response.headers.get("content-type", "").lower()
    if "json" not in ctype:
        return bool(cpf_matches(response))
    try:
        data = json.loads(response.text)
    except ValueError:
        return False
    if not data or not isinstance(data, (list, dict)):
        return False
    if isinstance(data, dict):
        if any(k.lower() in ("error", "errors", "exception") for k in data):
            return False
        if set(data) <= {"message", "status", "success", "ok", "detail"}:
            return False
    return not (len(response.body) < 200 and ERROR_CONTEXT.search(response.text))


def equivalent(left, right):
    if left.truncated or right.truncated:
        return False
    if left.headers.get("content-type", "").split(";")[0] != right.headers.get("content-type", "").split(";")[0]:
        return False
    try:
        return json.loads(left.text) == json.loads(right.text)
    except ValueError:
        return left.body.strip() == right.body.strip()


def response_evidence(response):
    return {"method": response.method, "status": response.status,
            "content_type": response.headers.get("content-type", ""), "bytes": len(response.body),
            "body_sha256": hashlib.sha256(response.body).hexdigest(),
            "session": response.session, "truncated": response.truncated}


class Detectors:
    def __init__(self, redactor):
        self.redactor = redactor
        self.findings = {}
        self.observations = []

    def pii(self, response):
        if response.session == "credential_exchange":
            return
        matches = cpf_matches(response)
        if not matches:
            return
        key = "cpf:" + fingerprint(response.url)
        old = self.findings.get(key)
        if old and old["evidence"]["access_context"] == "anonymous":
            return
        anonymous = response.session == "anonymous"
        self.findings[key] = {
            "id": key, "type": "sensitive_data_exposure", "severity": "high" if anonymous else "medium",
            "confidence": "high", "url": self.redactor.url(response.url), "method": response.method,
            "title": "Unmasked Brazilian CPF in HTTP response", "cwe": "CWE-359",
            "description": "Checksum-valid CPF identifiers appear in a CPF/document-labelled response context.",
            "why_it_matters": "Unmasked personal identifiers increase privacy and identity-fraud risk. " + (
                "This response was obtained without scanner-supplied authentication."
                if anonymous else "This is authenticated data exposure; user authorization and business necessity are not established by this test."),
            "evidence": {"response": response_evidence(response), "cpf_count": len({m['digits'] for m in matches}),
                         "value": "[CPF REDACTED]", "validation": "both CPF check digits and contextual label",
                         "access_context": response.session, "authorization_assessed": False},
            "remediation": "Minimize returned personal data; mask CPF where a full identifier is unnecessary and enforce access controls.",
        }

    def method(self, endpoint, baseline, probe, confirmation, control, reference=None):
        """Return a finding only with reproducible, non-generic evidence."""
        if not useful(probe) or not useful(confirmation) or not equivalent(probe, confirmation):
            return False
        if control is None or (control.status == probe.status and equivalent(control, probe)):
            return False  # Wildcard handler/SPA fallback, not a method-specific result.
        bypass = (baseline.status in (401, 403) and probe.session == "anonymous"
                  and (reference is not None and useful(reference) and equivalent(reference, probe)
                       or bool(cpf_matches(probe))))
        contract = (bool(endpoint.declared_methods) and probe.method not in endpoint.declared_methods
                    and useful(baseline) and equivalent(baseline, probe))
        if not bypass and not contract:
            return False
        mode = "authorization_bypass" if bypass else "declared_method_violation"
        key = "method:" + fingerprint(endpoint.url + mode)
        if key in self.findings:
            methods = self.findings[key]["evidence"]["confirmed_methods"]
            if probe.method not in methods:
                methods.append(probe.method)
            return True
        evidence = {"mode": mode, "baseline": response_evidence(baseline),
                    "alternate": response_evidence(probe), "confirmation": response_evidence(confirmation),
                    "unknown_method_control": response_evidence(control),
                    "confirmed_methods": [probe.method], "declared_methods": sorted(endpoint.declared_methods)}
        if reference is not None:
            evidence["authenticated_reference"] = response_evidence(reference)
        self.findings[key] = {
            "id": key, "type": "http_method_tampering", "severity": "high" if bypass else "medium",
            "confidence": "high", "url": self.redactor.url(endpoint.url), "method": probe.method,
            "title": "HTTP method changes bypass authorization" if bypass else "Endpoint violates its discovered method contract",
            "cwe": "CWE-863" if bypass else "CWE-650",
            "description": "A repeatable alternate-method response passes the evidence gates and differs from the unknown-method control.",
            "why_it_matters": "An anonymous alternate method exposes protected response data." if bypass else
                              "An undeclared method returns the same application data despite an explicit discovered method contract.",
            "evidence": evidence,
            "remediation": "Apply authentication and authorization to every method; reject unsupported methods before executing handlers.",
        }
        return True
