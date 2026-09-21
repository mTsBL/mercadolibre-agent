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
    # A CPF/document label anywhere in a structured response (e.g. a CSV column header or a
    # JSON "cpf" key) labels every value in that structure, not only the one within 100 chars.
    # Establish document-level context so later rows are not silently dropped from the count.
    document_context = bool(CPF_CONTEXT.search(text))
    matches = []
    for match in CPF_PATTERN.finditer(text):
        if not valid_cpf(match[0]):
            continue
        context = text[max(0, match.start() - 100):match.end() + 50]
        if document_context or CPF_CONTEXT.search(context):
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


LOGIN_REDIRECT = re.compile(r"/(?:login|log-in|signin|sign-in|entrar|acessar|auth|sso)(?:[/?#]|$)", re.I)
NEXT_PARAM = re.compile(r"[?&](?:next|return|returnurl|redirect|continue|dest)=", re.I)


def is_denied(response):
    """The actor was explicitly refused: an auth status, or a redirect to a login wall."""
    if response.status in (401, 403):
        return True
    if 300 <= response.status < 400:
        location = response.headers.get("location", "")
        if LOGIN_REDIRECT.search(location) or NEXT_PARAM.search(location):
            return True
    return False


def grant_kind(response, method, control):
    """Classify how a method grants access, or None. A control-equivalent response is a
    catch-all handler, not a method-specific grant. GET/HEAD returning a page is NOT a grant
    (that is the normal "you may read but not submit" pattern); only a write returning data,
    or any method performing an action (state-changing redirect / created / no-content), counts."""
    if response.truncated or method in ("HEAD", "OPTIONS"):
        return None
    if control is not None and control.status == response.status and equivalent(control, response):
        return None
    if 300 <= response.status < 400 and response.headers.get("location") and not is_denied(response):
        return "action"
    write = method in ("POST", "PUT", "PATCH", "DELETE")
    if response.status in (201, 204) and write:
        return "action"
    if response.status == 200 and write and useful(response):
        return "data"
    return None


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

    def correlate(self):
        """Link a CPF exposure to a method-tampering finding on the same URL: in isolation the
        exposure cannot assess authorization, but a bypass on that URL shows the access is improper."""
        tampering = {f["url"]: f["id"] for f in self.findings.values() if f["type"] == "http_method_tampering"}
        for finding in self.findings.values():
            related = finding["type"] == "sensitive_data_exposure" and tampering.get(finding["url"])
            if related:
                finding["evidence"]["authorization_assessed"] = True
                finding["evidence"]["related_findings"] = [related]
                finding["why_it_matters"] += (" A method-tampering finding on the same URL shows this access is improper: "
                    "the data is reachable through an unintended method that bypasses the intended authorization.")

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

    def record_bypass(self, endpoint, denied, granted, confirmation, control, method_name,
                      state_before=None, state_after=None):
        """The same actor is refused on one method but served by another: an authorization
        check applied to only some HTTP verbs. Evidence is already validated by the caller.
        When state_before/state_after are given, the finding also carries observable proof that
        the alternate method mutated state (not merely returned a success-looking status)."""
        key = "method:" + fingerprint(endpoint.url + "authorization_bypass")
        if key in self.findings:
            methods = self.findings[key]["evidence"]["confirmed_methods"]
            if method_name not in methods:
                methods.append(method_name)
            return True
        mutation = state_before is not None and state_after is not None
        evidence = {"mode": "authorization_bypass", "baseline": response_evidence(denied),
                    "alternate": response_evidence(granted), "confirmation": response_evidence(confirmation),
                    "unknown_method_control": response_evidence(control),
                    "confirmed_methods": [method_name], "declared_methods": sorted(endpoint.declared_methods)}
        if mutation:
            evidence["state_before"] = response_evidence(state_before)
            evidence["state_after"] = response_evidence(state_after)
        self.findings[key] = {
            "id": key, "type": "http_method_tampering", "severity": "high", "confidence": "high",
            "url": self.redactor.url(endpoint.url), "method": method_name,
            "title": "HTTP method bypasses authorization", "cwe": "CWE-863",
            "description": ("The intended write method, authenticated with a valid CSRF token, is denied, "
                            "yet the same actor performs the very operation via another method — proven by the "
                            "resource state changing between the recorded before and after snapshots."
                            if mutation else
                            "The same actor is denied on one HTTP method but obtains the resource or performs the "
                            "action via another, differing from the unknown-method control."),
            "why_it_matters": "An authorization check applied to only some HTTP methods lets a caller bypass it by switching the method.",
            "evidence": evidence,
            "remediation": "Apply the authorization check on every method (or share one handler); reject unsupported methods before executing.",
        }
        return True

    def record_contract(self, endpoint, baseline, probe, confirmation, control):
        """A method outside the declared contract returns the same data as the baseline GET."""
        key = "method:" + fingerprint(endpoint.url + "declared_method_violation")
        if key in self.findings:
            methods = self.findings[key]["evidence"]["confirmed_methods"]
            if probe.method not in methods:
                methods.append(probe.method)
            return True
        self.findings[key] = {
            "id": key, "type": "http_method_tampering", "severity": "medium", "confidence": "high",
            "url": self.redactor.url(endpoint.url), "method": probe.method,
            "title": "Endpoint violates its discovered method contract", "cwe": "CWE-650",
            "description": "A method outside the endpoint's declared contract returns the same application data as the baseline, differing from the unknown-method control.",
            "why_it_matters": "An undeclared method returns the same application data despite an explicit discovered method contract.",
            "evidence": {"mode": "declared_method_violation", "baseline": response_evidence(baseline),
                         "alternate": response_evidence(probe), "confirmation": response_evidence(confirmation),
                         "unknown_method_control": response_evidence(control),
                         "confirmed_methods": [probe.method], "declared_methods": sorted(endpoint.declared_methods)},
            "remediation": "Restrict each route to its intended methods and reject the rest before executing handlers.",
        }
        return True

    def record_unsafe_method(self, endpoint, intended, action, confirmation, control, method_name,
                             legitimate=None, state_before=None, state_after=None):
        """A safe method (GET) performs a state-changing action it should never perform. This is
        distinct from an authorization bypass: the actor may be allowed to perform the action via
        the proper write method, but the safe method reaches it without the CSRF token that method
        requires. `legitimate` is the intended write (with token) succeeding; state_before/after
        are the observable mutation."""
        key = "method:" + fingerprint(endpoint.url + "unsafe_method_state_change")
        if key in self.findings:
            methods = self.findings[key]["evidence"]["confirmed_methods"]
            if method_name not in methods:
                methods.append(method_name)
            return True
        evidence = {"mode": "unsafe_method_state_change", "baseline": response_evidence(intended),
                    "alternate": response_evidence(action), "confirmation": response_evidence(confirmation),
                    "unknown_method_control": response_evidence(control),
                    "confirmed_methods": [method_name], "declared_methods": sorted(endpoint.declared_methods)}
        if legitimate is not None:
            evidence["legitimate_method"] = response_evidence(legitimate)
        if state_before is not None and state_after is not None:
            evidence["state_before"] = response_evidence(state_before)
            evidence["state_after"] = response_evidence(state_after)
        self.findings[key] = {
            "id": key, "type": "http_method_tampering", "severity": "high", "confidence": "high",
            "url": self.redactor.url(endpoint.url), "method": method_name,
            "title": "State-changing action reachable via a safe HTTP method", "cwe": "CWE-352",
            "description": "A safe method (GET) performs a state-changing operation (an HTTP 303 See Other to its result) while the intended write method requires a CSRF token, so the safe method reaches the action without one.",
            # SameSite=Lax (the common default) still sends the session cookie on a top-level GET
            # navigation, so a victim following a crafted link triggers the action; it is NOT sent
            # for a cross-site subresource such as an <img>, so that vector is blocked under Lax.
            "why_it_matters": "Because a safe method mutates state without a CSRF token, an attacker can trigger it by luring the victim to follow a crafted link (a top-level GET navigation still carries a SameSite=Lax session cookie). A cross-site subresource such as an image does not carry a Lax cookie, so that vector is blocked; SameSite=None or a token check would be needed to stop the link vector too.",
            "evidence": evidence,
            "remediation": "Restrict state-changing operations to unsafe methods (POST/PUT/DELETE), require a CSRF token, and reject safe methods before executing the handler.",
        }
        return True
