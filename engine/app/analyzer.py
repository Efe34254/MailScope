from __future__ import annotations
import hashlib, ipaddress, math, re, uuid
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from .auth_verifier import verify_email_authentication
from .container_analysis import expand_nested_attachments
from .models import Address, AnalysisResult, Attachment, EmailContent, EmailData, Finding, IOC, RiskAssessment, SourceInfo, ToolReport
from .risk_engine import assess_risk
from .static_tools import scan_attachment

URL_RE = re.compile(r"https?://[^\s<>\"'()]+", re.I)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._ -]+")
PRIVATE_DOMAIN_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".home", ".test", ".invalid", ".localhost", ".example")
URGENCY_RE = re.compile(r"\b(urgent|immediately|verify|suspend|limited time|act now|payment failed|account locked|acil|hemen|doğrula|askıya)\b", re.I)

class HtmlSignals(HTMLParser):
    def __init__(self):
        super().__init__(); self.forms=0; self.scripts=0; self.iframes=0; self.images=0; self.tracking=0; self.hidden=0; self.links=[]
    def handle_starttag(self, tag, attrs):
        a=dict(attrs); tag=tag.lower()
        if tag=="form": self.forms+=1
        elif tag=="script": self.scripts+=1
        elif tag=="iframe": self.iframes+=1
        elif tag=="img":
            self.images+=1
            w=str(a.get("width","")).lower(); h=str(a.get("height","")).lower(); style=str(a.get("style","")).lower()
            if (w in {"0","1","1px"} and h in {"0","1","1px"}) or "display:none" in style: self.tracking+=1
        for attribute in ("href", "src", "action", "background"):
            if a.get(attribute): self.links.append(str(a[attribute]))
        if "display:none" in str(a.get("style","")).replace(" ","").lower() or a.get("hidden") is not None: self.hidden+=1

def _decode(v):
    if not v: return ""
    try: return str(make_header(decode_header(v)))
    except Exception: return str(v)

def _addresses(values):
    out=[]
    for name,address in getaddresses(values):
        address=address.strip().lower()
        if address: out.append(Address(display_name=_decode(name),address=address,domain=address.rsplit("@",1)[1] if "@" in address else ""))
    return out

def _hash(data): return {"md5":hashlib.md5(data).hexdigest(),"sha1":hashlib.sha1(data).hexdigest(),"sha256":hashlib.sha256(data).hexdigest()} # nosec

def _entropy(data):
    if not data:return 0.0
    c=Counter(data); n=len(data)
    return round(-sum((v/n)*math.log2(v/n) for v in c.values()),3)

def _file_type(data):
    sigs=[(b"MZ","PE executable"),(b"%PDF-","PDF document"),(b"PK\x03\x04","ZIP/Office archive"),(b"\xD0\xCF\x11\xE0","OLE compound document"),(b"\x7fELF","ELF executable"),(b"Rar!","RAR archive"),(b"\x1f\x8b","GZIP archive"),(b"7z\xbc\xaf'\x1c","7-Zip archive"),(b"\x89PNG\r\n\x1a\n","PNG image"),(b"\xff\xd8\xff","JPEG image"),(b"GIF8","GIF image")]
    for sig,name in sigs:
        if data.startswith(sig): return name
    return "text/script" if data[:512].decode("utf-8",errors="ignore").strip() else "unknown"

def _normalize_url(v):
    v=v.rstrip(".,;:!?)\"]}")
    try:
        p=urlsplit(v); host=(p.hostname or "").lower(); port=f":{p.port}" if p.port else ""
        return urlunsplit((p.scheme.lower(),host+port,p.path,p.query,""))
    except ValueError:return v

def _valid_domain(v):
    v=v.strip().lower().rstrip(".")
    if len(v)>253 or "." not in v or "=" in v or any(c.isspace() for c in v): return False
    labels=v.split(".")
    return all(label and len(label)<=63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",label,re.I) for label in labels)

def _valid_url(v):
    try:
        parsed=urlsplit(v)
        if parsed.scheme.lower() not in {"http","https"} or not parsed.hostname: return False
        try: ipaddress.ip_address(parsed.hostname)
        except ValueError:
            if not _valid_domain(parsed.hostname): return False
        parsed.port
        return True
    except (TypeError,ValueError): return False

def _entropy_is_suspicious(dtype,ext,entropy):
    if entropy<=7.2: return False
    compressed_or_media={"PDF document","ZIP/Office archive","OLE compound document","RAR archive","GZIP archive","7-Zip archive","PNG image","JPEG image","GIF image"}
    compressed_extensions={".pdf",".zip",".docx",".xlsx",".pptx",".doc",".xls",".ppt",".rar",".gz",".7z",".png",".jpg",".jpeg",".gif",".webp",".mp3",".mp4",".avi",".mov"}
    if dtype in compressed_or_media or ext in compressed_extensions: return False
    return dtype in {"PE executable","ELF executable","unknown"} or ext in {".exe",".dll",".scr",".sys",".com"}

def _public_host(value):
    host = str(value or "").strip().lower().rstrip(".")
    if not host or host == "localhost" or "." not in host or host.endswith(PRIVATE_DOMAIN_SUFFIXES):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return _valid_domain(host)


def _public(v,t):
    if t in {"ipv4","ipv6"}:
        try:return ipaddress.ip_address(v).is_global
        except:return False
    if t == "url":
        try:
            parsed = urlsplit(v)
            return parsed.scheme.lower() in {"http", "https"} and _public_host(parsed.hostname)
        except (TypeError, ValueError):
            return False
    if t == "email":
        return "@" in v and _public_host(v.rsplit("@", 1)[1])
    return _public_host(v)

def analyze_eml(file_path:Path,workspace:Path,revalidate_auth:bool=False,trusted_authserv_ids:list[str]|None=None)->AnalysisResult:
    raw=file_path.read_bytes(); msg=BytesParser(policy=policy.default).parsebytes(raw)
    raw_source_preview=raw[:100_000].decode("utf-8",errors="replace")
    if len(raw)>100_000:
        raw_source_preview+="\n\n[MailScope: raw RFC822 source preview truncated after 100,000 bytes.]"
    aid=f"anl_{uuid.uuid4()}"; created=datetime.now(timezone.utc).isoformat(); adir=workspace/aid/"attachments"; adir.mkdir(parents=True,exist_ok=True)
    texts=[]; htmls=[]; attachments=[]; findings=[]; reports=[]
    def finding(sev,cat,title,desc,evidence,tool): findings.append(Finding(finding_id=f"fnd_{uuid.uuid4()}",severity=sev,category=cat,title=title,description=desc,evidence=evidence,tool_id=tool))
    for idx,part in enumerate(msg.walk(),1):
        if part.is_multipart():continue
        disp=part.get_content_disposition(); filename=part.get_filename(); ctype=part.get_content_type(); payload=part.get_payload(decode=True) or b""
        if disp=="attachment" or filename:
            original=_decode(filename) or f"attachment-{idx}.bin"; safe=SAFE_NAME_RE.sub("_",Path(original).name).strip(" .")[:180] or f"attachment-{idx}.bin"; dest=adir/f"{idx:03d}-{safe}"; dest.write_bytes(payload)
            dtype=_file_type(payload); flags=[]; ext=Path(original).suffix.lower(); entropy=_entropy(payload)
            if dtype=="PE executable" and ext not in {".exe",".dll",".scr",".sys"}: flags.append("Executable content does not match the file extension")
            if _entropy_is_suspicious(dtype,ext,entropy): flags.append("High entropy may indicate packing or encryption")
            if ext in {".js",".jse",".vbs",".vbe",".ps1",".bat",".cmd",".scr",".hta",".lnk",".iso",".img"}: flags.append("Potentially dangerous attachment extension")
            for flag in flags:finding("high" if "Executable" in flag else "medium","attachment",flag,f"Attachment {original}: {flag}",original,"attachment_static")
            attachments.append(Attachment(attachment_id=f"att_{uuid.uuid4()}",file_name=original,sanitized_file_name=safe,declared_content_type=ctype,detected_type=dtype,size=len(payload),entropy=entropy,hashes=_hash(payload),stored_path=str(dest),static_flags=flags))
            continue
        try: content=part.get_content()
        except Exception: content=payload.decode(part.get_content_charset() or "utf-8",errors="replace")
        if isinstance(content,str):
            if ctype=="text/plain":texts.append(content)
            elif ctype=="text/html":htmls.append(content)
    extraction=expand_nested_attachments([item.model_dump() for item in attachments],adir)
    by_attachment_id={item.attachment_id:item for item in attachments}
    for attachment_id,update in extraction["updates"].items():
        target=by_attachment_id.get(attachment_id)
        if target:
            target.analysis_status=update.get("analysis_status",target.analysis_status)
            target.extraction_notes.extend(update.get("extraction_notes",[]))
    for child_data in extraction["artifacts"]:
        child=Attachment(**child_data)
        attachments.append(child)
        by_attachment_id[child.attachment_id]=child
        for flag in child.static_flags:
            finding("high" if "executable" in flag.lower() else "medium","attachment",flag,f"Embedded file {child.file_name}: {flag}",child.extracted_from,"container_extractor")
    if extraction["metrics"]["encrypted_items"]:
        finding("medium","attachment","Encrypted embedded content could not be analyzed","At least one encrypted PDF or archive member was detected. Encrypted content is not treated as clean.",str(extraction["metrics"]["encrypted_items"]),"container_extractor")
    if extraction["metrics"]["blocked_items"]:
        finding("medium","attachment","Container safety limit was reached","One or more embedded items were blocked by recursion, size, count, or compression-ratio limits.",str(extraction["metrics"]["blocked_items"]),"container_extractor")
    text="\n".join(texts); html="\n".join(htmls)
    decoded_headers="\n".join(f"{_decode(str(k))}: {_decode(str(v))}" for k,v in msg.items())
    hs=HtmlSignals()
    try:hs.feed(html)
    except Exception:pass
    # Scan only transfer-decoded MIME content and decoded headers. Scanning str(msg)
    # reintroduced quoted-printable soft breaks as malformed URLs such as https://f=.
    searchable="\n".join([text,unescape(html),decoded_headers])
    iocs=[]; seen=set()
    def add(t,v,loc):
        norm=v.lower().strip().rstrip(".") if t in {"domain","email"} else v; key=(t,norm)
        if not norm or key in seen:return
        if t=="domain" and not _valid_domain(norm): return
        seen.add(key); pub=_public(norm,t); iocs.append(IOC(ioc_id=f"ioc_{uuid.uuid4()}",type=t,value=v,normalized_value=norm,source={"component":"ioc_extractor","location":loc},classification={"scope":"public" if pub else "private","is_internal":not pub,"is_safe_to_query":pub}))
    urls=[]
    url_candidates=URL_RE.findall(searchable)+[unescape(v) for v in hs.links]
    for m in url_candidates:
        u=_normalize_url(m)
        if not _valid_url(u): continue
        urls.append(u); add("url",u,"decoded_body_or_headers")
        try:
            host=urlsplit(u).hostname
            if host:
                try: ip=ipaddress.ip_address(host); add("ipv4" if ip.version==4 else "ipv6",host,"url_host")
                except: add("domain",host,"url_host")
        except:pass
    for m in EMAIL_RE.findall(searchable):add("email",m,"decoded_body_or_headers");add("domain",m.rsplit("@",1)[1],"email_domain")
    for m in IP_RE.findall(searchable):
        try:ip=ipaddress.ip_address(m);add("ipv4" if ip.version==4 else "ipv6",str(ip),"decoded_body_or_headers")
        except:pass
    raw_headers="\n".join(f"{k}: {v}" for k,v in msg.items()); froms=_addresses(msg.get_all("from",[])); replies=_addresses(msg.get_all("reply-to",[]))
    from_domain=froms[0].domain if froms else ""; reply_domain=replies[0].domain if replies else ""
    # Authentication-Results is an upstream claim unless its producer is inside a configured trust boundary.
    auth_headers=msg.get_all("authentication-results",[])+msg.get_all("arc-authentication-results",[])
    auth="\n".join(auth_headers+msg.get_all("received-spf",[])).lower()
    auth_metrics={k:("pass" if re.search(rf"\b{k}=pass\b",auth) else "fail" if re.search(rf"\b{k}=(fail|softfail|permerror|temperror|neutral)\b",auth) else "not_found") for k in ("spf","dkim","dmarc")}
    claimed_authenticated=all(v=="pass" for v in auth_metrics.values())
    trusted_ids={str(value).strip().lower().rstrip(".") for value in (trusted_authserv_ids or []) if str(value).strip()}
    trusted_headers=[]
    for header in auth_headers:
        authserv_id=str(header).split(";",1)[0].strip().lower().rstrip(".")
        if authserv_id in trusted_ids:
            trusted_headers.append(str(header).lower())
    trusted_auth="\n".join(trusted_headers)
    trusted_metrics={k:("pass" if re.search(rf"\b{k}=pass\b",trusted_auth) else "fail" if re.search(rf"\b{k}=(fail|softfail|permerror|temperror|neutral)\b",trusted_auth) else "not_found") for k in ("spf","dkim","dmarc")}
    trusted_authenticated=bool(trusted_headers) and all(v=="pass" for v in trusted_metrics.values())
    header_trust="trusted_gateway" if trusted_headers else "unverified_header_claim"
    reports.append(ToolReport(tool_id="auth_headers",name="Authentication Results (Header Claims)",category="Headers",status="clean" if trusted_authenticated else "info" if claimed_authenticated else "warning",summary=f"CLAIMED: SPF {auth_metrics['spf'].upper()} · DKIM {auth_metrics['dkim'].upper()} · DMARC {auth_metrics['dmarc'].upper()}",metrics={**auth_metrics,"trust":header_trust,"trusted_header_count":len(trusted_headers),"configured_authserv_ids":len(trusted_ids),"trusted_spf":trusted_metrics["spf"],"trusted_dkim":trusted_metrics["dkim"],"trusted_dmarc":trusted_metrics["dmarc"]},details=["RFC 8601 Authentication-Results fields are assertions unless their authserv-id matches a locally configured trusted gateway."]))

    if revalidate_auth:
        verified_auth=verify_email_authentication(raw,msg)
        dkim_result=str(verified_auth.get("dkim",{}).get("result","unavailable"))
        spf_result=str(verified_auth.get("spf",{}).get("result","unavailable"))
        dmarc_result=str(verified_auth.get("dmarc",{}).get("result","unavailable"))
        dmarc_policy=str(verified_auth.get("dmarc",{}).get("policy",""))
        verification_status="clean" if dmarc_result=="pass" else "suspicious" if dmarc_result=="fail" else "warning" if dmarc_result not in {"unavailable","not_verifiable"} else "unavailable"
        if dmarc_result=="fail":
            severity="high" if dmarc_policy in {"quarantine","reject"} else "medium"
            finding(severity,"authentication","Independent DMARC validation failed",f"DNS-backed DKIM/SPF evaluation did not produce an aligned DMARC pass. Published policy: {dmarc_policy or 'unknown'}.","; ".join(verified_auth.get("dmarc",{}).get("details",[])[:3]),"auth_verification")
        reports.append(ToolReport(tool_id="auth_verification",name="Independent Email Authentication",category="Authentication",status=verification_status,summary=f"VERIFIED: DKIM {dkim_result.upper()} · SPF {spf_result.upper()} · DMARC {dmarc_result.upper()}",metrics={"dkim":dkim_result,"dkim_signatures":verified_auth.get("dkim",{}).get("signature_count",0),"spf":spf_result,"spf_client_ip":verified_auth.get("spf",{}).get("client_ip",""),"spf_domain":verified_auth.get("spf",{}).get("domain",""),"dmarc":dmarc_result,"dmarc_policy":dmarc_policy,"dmarc_policy_domain":verified_auth.get("dmarc",{}).get("policy_domain",""),"dkim_aligned":verified_auth.get("dmarc",{}).get("dkim_aligned",False),"spf_aligned":verified_auth.get("dmarc",{}).get("spf_aligned",False)},details=verified_auth.get("details",[])[:30]))
    else:
        verified_auth={"dkim":{"result":"disabled"},"spf":{"result":"disabled"},"dmarc":{"result":"disabled"}}
        dmarc_result="disabled"
        reports.append(ToolReport(tool_id="auth_verification",name="Independent Email Authentication",category="Authentication",status="unavailable",summary="DNS-backed verification is disabled with online intelligence.",metrics={"dkim":"disabled","spf":"disabled","dmarc":"disabled"},details=["Enable online intelligence and email authentication revalidation in Settings to perform DNS-backed checks."]))

    if dmarc_result=="pass": authenticated=True; authentication_source="independent_dmarc"
    elif dmarc_result=="fail": authenticated=False; authentication_source="independent_dmarc"
    elif trusted_authenticated:
        authenticated=True
        authentication_source="trusted_gateway"
    else:
        authenticated=False
        authentication_source="unverified_header_claim" if claimed_authenticated else "not_verified"
    # Identity
    mismatch=bool(from_domain and reply_domain and from_domain!=reply_domain)
    if mismatch:
        mismatch_severity="low" if authenticated else "medium"
        context="Independent SPF, DKIM, and DMARC validation passed, so the mismatch is informational context rather than standalone proof of spoofing." if authenticated else "Independent authentication was incomplete or did not pass; unverified header claims cannot reduce this risk."
        finding(mismatch_severity,"identity","Reply-To domain differs from From domain",f"From uses {from_domain}, while Reply-To uses {reply_domain}. {context}",f"{from_domain} → {reply_domain}","identity_guard")
    reports.append(ToolReport(tool_id="identity_guard",name="Sender Identity Guard",category="Identity",status="warning" if mismatch else "clean",summary="Authenticated Reply-To mismatch detected" if mismatch and authenticated else "Reply-To mismatch detected" if mismatch else "No basic sender identity mismatch detected",metrics={"from_domain":from_domain,"reply_to_domain":reply_domain,"mismatch":mismatch,"authentication_passed":authenticated,"authentication_source":authentication_source}))
    # HTML
    if hs.forms:finding("high","html","HTML form embedded in email",f"Found {hs.forms} form element(s).","<form>","html_inspector")
    if hs.scripts:finding("high","html","Script content embedded in email",f"Found {hs.scripts} script element(s).","<script>","html_inspector")
    if hs.iframes:finding("high","html","Iframe embedded in email",f"Found {hs.iframes} iframe element(s).","<iframe>","html_inspector")
    if hs.tracking:finding("low","privacy","Tracking pixel detected",f"Found {hs.tracking} likely tracking pixel(s).","1x1/hidden image","html_inspector")
    html_status="suspicious" if hs.forms or hs.scripts or hs.iframes else "warning" if hs.tracking or hs.hidden else "clean"
    reports.append(ToolReport(tool_id="html_inspector",name="HTML Inspector",category="Content",status=html_status,summary=f"Forms {hs.forms} · Scripts {hs.scripts} · Iframes {hs.iframes} · Tracking pixels {hs.tracking}",metrics={"forms":hs.forms,"scripts":hs.scripts,"iframes":hs.iframes,"images":hs.images,"tracking_pixels":hs.tracking,"hidden_elements":hs.hidden}))
    # URL and language
    unique_urls=len({u for u in urls}); redirects=sum(1 for u in urls if any(x in (urlsplit(u).hostname or "") for x in ("bit.ly","tinyurl","t.co","redirect","click","link")))
    reports.append(ToolReport(tool_id="ioc_extractor",name="IOC & URL Extractor",category="Indicators",status="info",summary=f"{unique_urls} unique URLs and {len(iocs)} total unique indicators",metrics={"unique_urls":unique_urls,"indicators":len(iocs),"redirect_like_hosts":redirects}))
    urgency=len(URGENCY_RE.findall(text+" "+re.sub("<[^>]+>"," ",html)))
    if urgency>=3:finding("medium","content","Urgency or pressure language detected",f"Detected {urgency} urgency-related terms.","language heuristic","content_linguistics")
    reports.append(ToolReport(tool_id="content_linguistics",name="Phishing Language Heuristics",category="Content",status="warning" if urgency>=3 else "clean",summary=f"{urgency} urgency/pressure term matches",metrics={"urgency_matches":urgency}))
    # Received chain and attachments
    received=msg.get_all("received",[])
    reports.append(ToolReport(tool_id="received_chain",name="Received Chain Analyzer",category="Headers",status="info",summary=f"{len(received)} Received hop(s) parsed",metrics={"hop_count":len(received)},details=[_decode(x)[:300] for x in received[:10]]))
    extraction_status="warning" if extraction["metrics"]["encrypted_items"] or extraction["metrics"]["blocked_items"] or extraction["metrics"]["unsupported_containers"] else "clean"
    reports.append(ToolReport(tool_id="container_extractor",name="Embedded File & Archive Extractor",category="Attachments",status=extraction_status,summary=f"Extracted {extraction['metrics']['embedded_files']} embedded file(s) within bounded recursion limits",metrics=extraction["metrics"],details=extraction["details"]))
    reports.append(ToolReport(tool_id="attachment_static",name="Attachment Static Analyzer",category="Attachments",status="suspicious" if any(a.static_flags for a in attachments) else "clean",summary=f"{len(attachments)} attachment(s), {sum(bool(a.static_flags) for a in attachments)} flagged",metrics={"attachments":len(attachments),"flagged":sum(bool(a.static_flags) for a in attachments)}))
    # Real local attachment tool integrations. Tools run only for relevant attachments.
    tool_runs={"worker_isolation":[],"yara":[],"pdf_analyzer":[],"office_analyzer":[],"pe_analyzer":[],"capa":[],"floss":[],"exiftool":[]}
    for att in attachments:
        scan_results=scan_attachment(Path(att.stored_path),att.detected_type)
        isolation_result=scan_results.get("worker_isolation",{})
        if isolation_result and not isolation_result.get("success",False):
            att.analysis_status="timed_out" if isolation_result.get("status")=="timed_out" else "tool_failed"
            failure_note=str(isolation_result.get("error") or "Isolated static-analysis worker failed")[:500]
            if failure_note not in att.extraction_notes: att.extraction_notes.append(failure_note)
        for tool_id,data in scan_results.items():
            tool_runs.setdefault(tool_id,[]).append((att.file_name,data))
    tool_meta={
      "worker_isolation":("Static Analysis Worker Isolation","Safety"),
      "yara":("YARA Rules","Detection"),"pdf_analyzer":("PDF Static Analyzer","Documents"),
      "office_analyzer":("Office Macro Analyzer","Documents"),"pe_analyzer":("PE Static Analyzer","Executables"),
      "capa":("capa Capability Analyzer","Executables"),"floss":("FLOSS String Extractor","Executables"),
      "exiftool":("ExifTool Metadata Analyzer","Metadata")}
    for tool_id,(name,category) in tool_meta.items():
        runs=tool_runs.get(tool_id,[])
        if not attachments:
            reports.append(ToolReport(tool_id=tool_id,name=name,category=category,status="info",summary="Skipped — no attachments")); continue
        if not runs:
            reports.append(ToolReport(tool_id=tool_id,name=name,category=category,status="info",summary="Skipped — no relevant attachment type")); continue
        available=[(n,d) for n,d in runs if d.get("available")]
        if not available:
            reports.append(ToolReport(tool_id=tool_id,name=name,category=category,status="unavailable",summary=runs[0][1].get("error","Tool unavailable"),details=[f"{n}: {d.get('error','unavailable')}" for n,d in runs[:8]])); continue
        successful=[(n,d) for n,d in available if d.get("success",True)]
        failed=[(n,d) for n,d in available if not d.get("success",True)]
        suspicious=False; suspicious_severity="medium"; details=[]; metrics={"files_scanned":len(successful),"files_failed":len(failed)}
        for fname,data in successful:
            for metric,value in data.get("metrics",{}).items():
                if isinstance(value,(int,float)) and not isinstance(value,bool): metrics[metric]=max(metrics.get(metric,0),value) if metric in {"rules_loaded","rule_files"} else metrics.get(metric,0)+value
                elif isinstance(value,str) and metric not in metrics: metrics[metric]=value
            if tool_id=="yara" and data.get("matches"):
                suspicious=True
                severities={str(match.get("severity","medium")) for match in data["matches"] if isinstance(match,dict)}
                suspicious_severity="high" if "high" in severities else "medium" if "medium" in severities else "low"
                for match in data["matches"][:20]:
                    if isinstance(match,dict): details.append(f"{fname}: {match.get('rule','unknown')} [{str(match.get('severity','medium')).upper()}] — {match.get('description','YARA rule matched')}")
                    else: details.append(f"{fname}: {match}")
            elif tool_id=="pdf_analyzer":
                bad=[k for k in ("javascript","open_action","launch","embedded_files") if data.get(k)]
                suspicious= suspicious or bool(bad); details.append(f"{fname}: pages={data.get('pages',0)}, flags={', '.join(bad) or 'none'}")
            elif tool_id=="office_analyzer":
                suspicious=suspicious or bool(data.get("has_macros")); details.append(f"{fname}: macros={data.get('macro_count',0)}")
            elif tool_id=="pe_analyzer":
                details.append(f"{fname}: entry={data.get('entry_point')}, sections={len(data.get('sections',[]))}")
            elif tool_id=="worker_isolation":
                details.extend(data.get("details",[])[:8])
                for metric,value in data.get("metrics",{}).items():
                    if value not in (None, ""): metrics[metric]=value
            elif tool_id in {"capa","floss","exiftool"}:
                tool_details=data.get("details",[])
                details.append(f"{fname}: completed with verified bundled {name}")
                details.extend(f"{fname}: {value}" for value in tool_details[:12])
                if data.get("output_truncated"): details.append(f"{fname}: output exceeded the 8 MiB safety limit and was truncated")
        for fname,data in failed:
            details.append(f"{fname}: {data.get('error','tool returned an error')}")
        if suspicious:
            if tool_id=="office_analyzer": suspicious_severity="high"
            finding(suspicious_severity,"attachment",f"{name} produced suspicious results",details[0] if details else name,"; ".join(details[:3]),tool_id)
        status="suspicious" if suspicious else "error" if not successful else "warning" if failed else "clean"
        summary=f"Scanned {len(successful)} attachment(s)" + (f"; {len(failed)} failed" if failed else "")
        reports.append(ToolReport(tool_id=tool_id,name=name,category=category,status=status,summary=summary,metrics=metrics,details=details[:30]))
    risk=RiskAssessment(**assess_risk(findings,reports))
    result=AnalysisResult(analysis_id=aid,created_at=created,status="completed",source=SourceInfo(file_name=file_path.name,file_size=len(raw),sha256=hashlib.sha256(raw).hexdigest()),email=EmailData(**{"from":froms[0] if froms else Address(),"subject":_decode(msg.get("subject")),"to":_addresses(msg.get_all("to",[])),"cc":_addresses(msg.get_all("cc",[])),"reply_to":replies,"return_path":_decode(msg.get("return-path")),"date":_decode(msg.get("date")),"message_id":_decode(msg.get("message-id")),"received":[_decode(v) for v in received],"content":EmailContent(text_available=bool(text),html_available=bool(html),text_length=len(text),html_length=len(html),text_preview=text[:20000],html_preview=html[:20000]),"raw_headers":raw_headers,"raw_source_preview":raw_source_preview}),iocs=iocs,attachments=attachments,findings=findings,tool_reports=reports,risk=risk)
    return result
