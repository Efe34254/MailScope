from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from email.utils import getaddresses
from typing import Any, Callable


DMARC_VERSION = "RFC 9989"
MAX_DKIM_SIGNATURES = 10
MAX_DMARC_QUERIES = 8


def _tag_values(value: str) -> dict[str, str]:
    return {
        match.group(1).lower(): match.group(2).strip()
        for match in re.finditer(r"(?:^|;)\s*([a-z][a-z0-9_]*)\s*=\s*([^;]*)", value, re.I)
    }


def _dkim_signatures(message: Message) -> list[dict[str, str]]:
    signatures = []
    for value in message.get_all("dkim-signature", [])[:MAX_DKIM_SIGNATURES]:
        tags = _tag_values(str(value).replace("\r", " ").replace("\n", " "))
        signatures.append({"domain": tags.get("d", "").lower().rstrip("."), "selector": tags.get("s", "")})
    return signatures


def _verify_dkim(raw: bytes, message: Message, dnsfunc: Callable[..., bytes | None] | None = None) -> dict[str, Any]:
    signatures = _dkim_signatures(message)
    if not signatures:
        return {"result": "none", "signature_count": 0, "valid_domains": [], "signatures": [], "details": ["No DKIM-Signature header is present."]}
    try:
        import dkim
    except Exception as exc:
        return {"result": "unavailable", "signature_count": len(signatures), "valid_domains": [], "signatures": signatures, "details": [f"DKIM verifier unavailable: {type(exc).__name__}"]}

    verifier = dkim.DKIM(raw, timeout=3, minkey=1024)
    checked = []
    valid_domains = []
    temporary_error = False
    resolver = dnsfunc or dkim.get_txt
    for index, signature in enumerate(signatures):
        entry = dict(signature)
        try:
            passed = bool(verifier.verify(idx=index, dnsfunc=resolver))
            entry["result"] = "pass" if passed else "fail"
            if passed and signature["domain"]:
                valid_domains.append(signature["domain"])
        except getattr(dkim, "DnsTimeoutError", Exception):
            entry["result"] = "temperror"
            temporary_error = True
        except Exception as exc:
            entry["result"] = "fail"
            entry["error"] = type(exc).__name__
        checked.append(entry)
    result = "pass" if valid_domains else "temperror" if temporary_error else "fail"
    details = [f"d={item.get('domain') or '?'}; s={item.get('selector') or '?'}: {item['result'].upper()}" for item in checked]
    return {"result": result, "signature_count": len(signatures), "valid_domains": sorted(set(valid_domains)), "signatures": checked, "details": details}


def _first_match(patterns: list[str], text: str) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1).strip().strip('"<>[](),;')
    return ""


def _spf_evidence(message: Message) -> dict[str, str]:
    received_spf = "\n".join(str(value) for value in message.get_all("received-spf", []))
    authentication = "\n".join(str(value) for value in message.get_all("authentication-results", []))
    searchable = received_spf + "\n" + authentication
    client_ip = _first_match([
        r"client-ip\s*=\s*([0-9a-f:.]+)",
        r"sender\s+IP\s+is\s+([0-9a-f:.]+)",
    ], searchable)
    envelope_from = _first_match([
        r"envelope-from\s*=\s*\"?([^\s;\"]+)",
        r"smtp\.mailfrom\s*=\s*\"?([^\s;\"]+)",
    ], searchable)
    if not envelope_from:
        envelope_from = str(message.get("return-path", "")).strip().strip("<>")
    helo = _first_match([
        r"(?:smtp\.)?helo\s*=\s*\"?([^\s;\"]+)",
    ], searchable)
    return {"client_ip": client_ip, "envelope_from": envelope_from, "helo": helo, "evidence_source": "recorded SMTP headers"}


def _verify_spf(message: Message, checker: Callable[..., tuple[str, str]] | None = None) -> dict[str, Any]:
    evidence = _spf_evidence(message)
    try:
        if evidence["client_ip"]:
            ipaddress.ip_address(evidence["client_ip"])
    except ValueError:
        evidence["client_ip"] = ""
    sender = evidence["envelope_from"]
    sender_domain = sender.rsplit("@", 1)[-1].lower().rstrip(".") if sender else ""
    if sender_domain and "@" not in sender:
        sender = f"postmaster@{sender_domain}"
    helo = evidence["helo"].lower().rstrip(".") or sender_domain
    if not evidence["client_ip"] or not sender_domain:
        return {"result": "not_verifiable", "domain": sender_domain, **evidence, "details": ["SPF needs a recorded SMTP client IP and envelope sender; one or both are missing."]}
    try:
        if checker is None:
            import spf
            checker = spf.check2
        result, explanation = checker(i=evidence["client_ip"], s=sender, h=helo, timeout=3, querytime=8)
        normalized = str(result).lower()
        if normalized not in {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}:
            normalized = "permerror"
        return {"result": normalized, "domain": sender_domain, **evidence, "helo": helo, "details": [str(explanation)[:500], "The SMTP IP is reconstructed from message headers and cannot be independently proven from an offline EML file."]}
    except Exception as exc:
        return {"result": "temperror", "domain": sender_domain, **evidence, "helo": helo, "details": [f"SPF re-evaluation failed: {type(exc).__name__}"]}


def _default_txt_lookup(name: str) -> list[str]:
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2.0
    resolver.lifetime = 3.0
    try:
        answer = resolver.resolve(name, "TXT", search=False)
        return [b"".join(record.strings).decode("utf-8", errors="replace") for record in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        raise TimeoutError(type(exc).__name__) from exc


def _tree_targets(domain: str) -> list[str]:
    labels = [label for label in domain.lower().rstrip(".").split(".") if label]
    if not labels:
        return []
    targets = [".".join(labels)]
    remaining = labels[1:] if len(labels) < MAX_DMARC_QUERIES else labels[-7:]
    while remaining and len(targets) < MAX_DMARC_QUERIES:
        target = ".".join(remaining)
        if target not in targets:
            targets.append(target)
        remaining = remaining[1:]
    return targets


def _valid_dmarc_record(records: list[str]) -> tuple[str, dict[str, str]] | None:
    candidates = [record.strip() for record in records if re.match(r"^v\s*=\s*DMARC1(?:\s*;|$)", record.strip(), re.I)]
    if len(candidates) != 1:
        return None
    return candidates[0], _tag_values(candidates[0])


def _cached_lookup(lookup: Callable[[str], list[str]]) -> Callable[[str], list[str]]:
    cache: dict[str, list[str]] = {}

    def run(name: str) -> list[str]:
        if name not in cache:
            cache[name] = lookup(name)
        return cache[name]

    setattr(run, "cache", cache)
    return run


def _discover_dmarc_policy(author_domain: str, lookup: Callable[[str], list[str]]) -> dict[str, Any]:
    queried = []
    for target in _tree_targets(author_domain):
        name = f"_dmarc.{target}"
        queried.append(name)
        valid = _valid_dmarc_record(lookup(name))
        if valid:
            record, tags = valid
            policy = tags.get("p", "").lower()
            if target != author_domain:
                policy = tags.get("sp", policy).lower()
            if policy not in {"none", "quarantine", "reject"}:
                return {"result": "invalid", "policy_domain": target, "record": record, "tags": tags, "queried": queried}
            return {"result": "found", "policy_domain": target, "policy": policy, "record": record, "tags": tags, "queried": queried}
    return {"result": "none", "policy_domain": "", "policy": "", "record": "", "tags": {}, "queried": queried}


def _organizational_domain(domain: str, lookup: Callable[[str], list[str]]) -> str:
    found: list[tuple[str, dict[str, str]]] = []
    labels = domain.lower().rstrip(".").split(".")
    for target in _tree_targets(domain):
        valid = _valid_dmarc_record(lookup(f"_dmarc.{target}"))
        if not valid:
            continue
        _, tags = valid
        found.append((target, tags))
        if tags.get("psd", "").lower() == "n":
            return target
        if tags.get("psd", "").lower() == "y":
            target_labels = target.split(".")
            if len(labels) > len(target_labels):
                return ".".join(labels[-(len(target_labels) + 1):])
    if found:
        return min((target for target, _ in found), key=lambda value: len(value.split(".")))
    return domain.lower().rstrip(".")


def _aligned(author: str, authenticated: str, mode: str, lookup: Callable[[str], list[str]]) -> bool:
    author = author.lower().rstrip(".")
    authenticated = authenticated.lower().rstrip(".")
    if not author or not authenticated:
        return False
    if author == authenticated:
        return True
    if mode == "s":
        return False
    return _organizational_domain(author, lookup) == _organizational_domain(authenticated, lookup)


def _evaluate_dmarc(author_domain: str, dkim_result: dict[str, Any], spf_result: dict[str, Any], txt_lookup: Callable[[str], list[str]] | None = None) -> dict[str, Any]:
    if not author_domain:
        return {"result": "not_verifiable", "details": ["DMARC needs exactly one valid RFC5322.From domain."]}
    lookup = _cached_lookup(txt_lookup or _default_txt_lookup)
    try:
        policy = _discover_dmarc_policy(author_domain, lookup)
        if policy["result"] == "none":
            return {**policy, "result": "none", "dkim_aligned": False, "spf_aligned": False, "details": ["No applicable DMARC policy record was discovered."]}
        if policy["result"] == "invalid":
            return {**policy, "dkim_aligned": False, "spf_aligned": False, "details": ["The discovered DMARC record is invalid or lacks a valid policy."]}
        tags = policy["tags"]
        dkim_aligned = any(_aligned(author_domain, domain, tags.get("adkim", "r").lower(), lookup) for domain in dkim_result.get("valid_domains", []))
        spf_aligned = spf_result.get("result") == "pass" and _aligned(author_domain, str(spf_result.get("domain", "")), tags.get("aspf", "r").lower(), lookup)
        result = "pass" if dkim_aligned or spf_aligned else "fail"
        return {**policy, "result": result, "dkim_aligned": dkim_aligned, "spf_aligned": spf_aligned, "author_domain": author_domain, "standard": DMARC_VERSION, "details": [f"Policy {policy['policy'].upper()} at {policy['policy_domain']}", f"DKIM aligned: {dkim_aligned}; SPF aligned: {spf_aligned}"]}
    except TimeoutError as exc:
        return {"result": "temperror", "policy_domain": "", "policy": "", "dkim_aligned": False, "spf_aligned": False, "standard": DMARC_VERSION, "details": [f"DMARC DNS lookup timed out: {exc}"]}
    except Exception as exc:
        return {"result": "temperror", "policy_domain": "", "policy": "", "dkim_aligned": False, "spf_aligned": False, "standard": DMARC_VERSION, "details": [f"DMARC evaluation failed: {type(exc).__name__}"]}


def verify_email_authentication(raw: bytes, message: Message, txt_lookup: Callable[[str], list[str]] | None = None, dkim_dnsfunc: Callable[..., bytes | None] | None = None, spf_checker: Callable[..., tuple[str, str]] | None = None) -> dict[str, Any]:
    from_domains = [address.rsplit("@", 1)[1].lower().rstrip(".") for _, address in getaddresses(message.get_all("from", [])) if "@" in address]
    author_domain = from_domains[0] if len(from_domains) == 1 else ""
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="mailscope-auth") as pool:
        dkim_future = pool.submit(_verify_dkim, raw, message, dkim_dnsfunc)
        spf_future = pool.submit(_verify_spf, message, spf_checker)
        dkim_result = dkim_future.result()
        spf_result = spf_future.result()
    dmarc_result = _evaluate_dmarc(author_domain, dkim_result, spf_result, txt_lookup)
    details = ["Independent DKIM verification uses the original message bytes and DNS public key."]
    details.extend(dkim_result.get("details", []))
    details.extend(spf_result.get("details", []))
    details.extend(dmarc_result.get("details", []))
    return {"author_domain": author_domain, "dkim": dkim_result, "spf": spf_result, "dmarc": dmarc_result, "details": details[:30]}
