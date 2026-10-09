"""Deterministic, regex-signature based threat detection and IOC extraction.

This layer is intentionally free of any network calls: it always returns the
same verdict for the same input, needs no API keys, and never hallucinates.
Live reputation data is layered on top of it elsewhere.
"""

import re
from typing import Any

IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b")
URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
WALLET_REGEX = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[02-9ac-hj-np-z]{11,71})\b")
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|top|ru|cn|info|biz|cc|tk|onion|site|live|click|co|me)\b",
    re.IGNORECASE,
)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Addresses reserved for documentation (RFC 5737) or private use (RFC 1918).
# These are not routable on the public internet, so public reputation feeds
# legitimately have no data for them and must not be treated as "clean".
DOCUMENTATION_PREFIXES = {
    "192.0.2": "TEST-NET-1 (RFC 5737, documentation)",
    "198.51.100": "TEST-NET-2 (RFC 5737, documentation)",
    "203.0.113": "TEST-NET-3 (RFC 5737, documentation)",
    "192.168": "Private LAN (RFC 1918)",
    "10": "Private LAN (RFC 1918)",
    "127": "Loopback (RFC 1122)",
}


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 0)


def documentation_label(ip: str) -> str | None:
    """Return a reserved-range label for the IP, or None if it is public."""
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    if not all(0 <= o <= 255 for o in octets):
        return None

    two = f"{octets[0]}.{octets[1]}"
    if octets[0] == 192 and octets[1] == 0 and octets[2] == 2:
        return DOCUMENTATION_PREFIXES["192.0.2"]
    if octets[0] == 198 and octets[1] == 51 and octets[2] == 100:
        return DOCUMENTATION_PREFIXES["198.51.100"]
    if octets[0] == 203 and octets[1] == 0 and octets[2] == 113:
        return DOCUMENTATION_PREFIXES["203.0.113"]
    if octets[0] == 192 and octets[1] == 168:
        return DOCUMENTATION_PREFIXES["192.168"]
    if octets[0] == 10:
        return DOCUMENTATION_PREFIXES["10"]
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return "Private LAN (RFC 1918)"
    if octets[0] == 127:
        return DOCUMENTATION_PREFIXES["127"]
    if octets[0] == 0:
        return "This-network (RFC 1122)"
    return None


def is_public_ip(ip: str) -> bool:
    return documentation_label(ip) is None


class Signature:
    """One regex signature plus the metadata needed to explain a match."""

    def __init__(
        self,
        key: str,
        label: str,
        pattern: str,
        severity: str,
        category: str,
        explanation: str,
        remediation: str,
    ) -> None:
        self.key = key
        self.label = label
        self.category = category
        self.severity = severity
        self.explanation = explanation
        self.remediation = remediation
        self.regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)

    def to_dict(self, hits: list[Any]) -> dict[str, Any]:
        samples = []
        for hit in hits[:3]:
            if isinstance(hit, tuple):
                samples.append(" ".join(g for g in hit if g).strip()[:120])
            else:
                samples.append(str(hit)[:120])
        return {
            "key": self.key,
            "label": self.label,
            "category": self.category,
            "severity": self.severity,
            "matches_found": len(hits),
            "explanation": self.explanation,
            "remediation": self.remediation,
            "samples": samples,
        }


SIGNATURES: list[Signature] = [
    Signature(
        "ssh_brute_force",
        "SSH Brute-Force / Password Spraying",
        r"Failed password for|Failed \S+ for invalid user|authentication failure.*sshd|"
        r"Invalid user \S+ from|maximum authentication attempts exceeded|"
        r"(?:Failed|Invalid|Unauthorized|ERROR:)?\s*(?:login|log ?in|sign ?in|attempt)\s+"
        r"(?:from|for|using|by)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"(?:Failed|Invalid)\s+(?:login|log ?in|password|publickey)\s+for\s+",
        "high",
        "intrusion",
        "Someone is guessing SSH passwords automatically, over and over, against your server. "
        "This is almost never a real person - it is a bot cycling through the most common "
        "passwords (root, admin, oracle, pi...) hoping one works. Picture someone standing at "
        "your door trying thousands of keys in a row.",
        "Block the source addresses, move SSH off a public port, disable password auth for "
        "root, and let fail2ban auto-ban repeat offenders.",
    ),
    Signature(
        "sql_injection",
        "SQL Injection Attempt",
        r"\bOR\s+'?1'?\s*=\s*'?1\b|\bOR\s+'?[0-9a-z]+'?\s*=\s*'?[0-9a-z]+'?\b(?!\s*=)|"
        r"\bUNION\s+(?:ALL\s+)?SELECT\b|\b(?:SELECT\b[^\n]{0,80}\bFROM\b[^\n]{0,80}(?:--|#|;))|"
        r"(?:'|%27)\s*(?:--|#|;|\bor\b)|\bDROP\s+TABLE\b|\bSLEEP\s*\(\s*\d+\s*\)|"
        r"\bBENCHMARK\s*\(|\bOR\s+SLEEP\b|\b(?:admin|root)['\"]?\s*%20?OR\b",
        "critical",
        "injection",
        "A visitor typed code into one of your web form fields to break out of it and talk "
        "straight to your database. The classic probe is ' OR 1=1 -- which asks the database to "
        "return every row instead of just one. When that works, an attacker can read, change, "
        "or destroy everything you store - and often take over the whole server.",
        "Use parameterised queries or an ORM instead of building SQL by string concatenation, "
        "run the app as a low-privilege database user, and block the source IP.",
    ),
    Signature(
        "phishing_indicators",
        "Phishing / Credential-Harvesting Indicators",
        r"click (?:the )?(?:secure |login )?(?:link|portal|below)|verify your account|"
        r"your account (?:will be|has been|is|was) (?:suspend|locked|expire|expir|disable)|"
        r"password (?:expires?|expiring|will expire)|action required|"
        r"reset your password|update your (?:account|credentials|information|details)|"
        r"security alert|unusual (?:activity|sign-?in)|verify your identity|"
        r"(?:has been|was|is) (?:locked|suspended)|confirm your (?:identity|password|details)|"
        r"dear (?:employee|customer|user|colleague|sir|madam|valued)",
        "high",
        "social_engineering",
        "This message is written to make you act before you think. It manufactures urgency, asks "
        "you to click a link or type your credentials into a fake portal, and usually pretends to "
        "be your IT team, a bank, or delivery company. No legitimate organisation will ever ask "
        "you to confirm a password through an email link.",
        "Do not click or reply. Verify the request through a channel you already trust (a phone "
        "number from the company directory, not the message). Report it and block the sender "
        "domain and URLs.",
    ),
    Signature(
        "ransomware_note",
        "Ransomware Extortion Note",
        r"all your files are encrypted|your files have been encrypted|"
        r"(?:decrypt(?:ion)? (?:key|tool|utility)|restore your (?:files|data))|"
        r"pay\s*[\d.]*\s*bitcoin|ransom (?:note|demand|payment|is due)|"
        r"files (?:will be|are going to be) (?:leaked|published|sold)|"
        r"double[d]? or (?:your data|everything)|"
        r"do not (?:rename|modify) (?:the encrypted|these) files",
        "critical",
        "malware",
        "This is a ransom note dropped by malware that has already encrypted your files. The "
        "attacker demands payment, usually in cryptocurrency, for a decryption key. Paying is "
        "never a guarantee of getting your files back, and this note almost always comes from "
        "an infostealer that already copied your data before encrypting it - so the real reason "
        "to act fast is data loss, not extortion.",
        "Isolate the host from the network right now, preserve the note and a memory image, and "
        "restore from known-good offline backups. Rotate every credential that touched the box. "
        "Never pay.",
    ),
    Signature(
        "bec_whaling",
        "Business Email Compromise / Whaling",
        r"gift ?cards?|(?:wire|bank) transfer[^\n]{0,40}(?:urgent|immediate|now)|"
        r"urgent[^\n]{0,40}(?:transfer|wire|deposit)|immediately buy|buy\s*\d+\s*x\s*\$|"
        r"corporate card[^\n]{0,30}(?:declin|reject|max|limit)|"
        r"(?:cannot|can't|unable to) (?:pick up|answer|call)|do not call me|"
        r"board meeting|keep (?:this|it) (?:between|secret|confidential)|"
        r"don'?t (?:tell|inform|alert|mention)|between us|confidential (?:deal|acquisition|project)|"
        r"my (?:card|credit card) (?:was |is )?(?:declined|rejected|blocked)",
        "high",
        "social_engineering",
        "This is a social-engineering attack aimed at a person rather than a machine. An attacker, "
        "often impersonating an executive or a supplier, stacks urgency and secrecy so an employee "
        "buys gift cards or sends money before anyone else can verify the request. The unusual "
        "detail - a phone number 'do not call me' number, a personal mobile, an odd payment method "
        "- is itself a red flag.",
        "Verify through a known-good channel: call back on the number in the company directory, "
        "never one supplied in the message. Report to IT and security immediately, and report "
        "the sender to your mail provider.",
    ),
    Signature(
        "cloud_credential_abuse",
        "Cloud Credential Abuse / Suspicious Audit Event",
        r'(?:sourceIPAddress|userIdentity|principalId|eventSource|eventName)"?\s*:\s*"|'
        r"\b(?:AWS|Azure|GCP|CloudTrail)\b[^\n]{0,40}(?:trail|audit|login|key)|"
        r"\b(?:ConsoleLogin|AssumeRole|accessDenied|InvalidClientTokenId|"
        r"UnrecognizedClientException|InvalidSignatureException|ExpiredToken|"
        r"CreateAccessKey|AttachUserPolicy|PutRolePolicy)\b|"
        r"\benumerat(?:e|ing)\s+(?:the\s+)?(?:buckets?|instances?|iam|roles?)|"
        r"\bMFAUsed\"?\s*:\s*\"?(?:No|false|False)",
        "high",
        "cloud",
        "This is cloud audit-log activity, and the shape of it is a warning sign. An attacker "
        "holding stolen or accidentally exposed access keys probes your cloud account from an "
        "unfamiliar address, often without MFA, enumerating what they can reach before making "
        "noise. Failed console logins are the reconnaissance stage that precedes privilege "
        "escalation, not an isolated event.",
        "Rotate the exposed credentials immediately, enforce MFA for every human and service "
        "account, review IAM trust policies for unexpected principals, and enable CloudTrail data "
        "events so file access is recorded too.",
    ),
    Signature(
        "malware_c2_callback",
        "Suspicious Malware Callback (C2 Beaconing)",
        r"\b(?:beacon(?:ing)?|call ?back to|command and control|C2 (?:server|address|beacon))\b|"
        r"(?:connected|connecting|phoning home) to \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"\bPOST /[a-z0-9_\-/]{1,40}\.php\b[^\n]{0,40}(?:200|204|500)|"
        r"\bPOST /[a-z0-9_\-]{1,20}\.(?:asp|aspx|jsp|php)\s+HTTP/",
        "high",
        "malware",
        "A process on your machine is phoning home to a remote server on a schedule. Malware "
        "beacons look like an ordinary program quietly reaching out to an attacker-controlled host "
        "to fetch new instructions or to hand over data it has collected. The periodic, "
        "low-volume, always-the-same-destination pattern is what separates it from normal traffic.",
        "Cut the host's outbound access, capture a memory image before power off, and treat the "
        "machine as untrusted until it is rebuilt from a clean image. Hunt for persistence across "
        "the rest of the fleet.",
    ),
    Signature(
        "port_scan",
        "Port Scan / Reconnaissance Activity",
        r"\bDPT=\d+|Nmap scan from|scan detected|"
        r"(?:multiple|several) ports[^\n]{0,40}(?:scanned|probe|open)|"
        r"\bSYN stealth scan\b|\bnmap\b[^\n]{0,60}\bscan\b",
        "medium",
        "recon",
        "Something is checking which of your ports are open, knocking on many doors to see what "
        "answers. This is nearly always step one of a real attack: the scan builds a map of your "
        "running services so the attacker knows exactly where to aim next.",
        "Close inbound ports you do not need, allow-list only required sources, and watch for a "
        "follow-up burst of connections to whatever the scan found open.",
    ),
    Signature(
        "privilege_escalation",
        "Privilege Escalation Attempt",
        r"sudo:[^\n]{0,80}(?:incorrect password|authentication failure|not in the sudoers)|"
        r"\bsu:\s*(?:FAILED|authentication failure)|"
        r"\b(?:setuid|privilege escalation|escalate(?:d|d)? privileges?)\b|"
        r"CVE-\d{4}-\d{4,7}[^\n]{0,60}(?:exploit|root|escalat)",
        "high",
        "privilege_escalation",
        "A low-privileged user or process is trying to become root. Either somebody is guessing "
        "the sudo password, or an exploit is being used to break out of a deliberately "
        "restricted account. Root on your server means full control: your keys, your database, "
        "and a launch pad for attacks on everything downstream.",
        "Review who holds sudo, keep sudoers minimal and NOPASSWD-free, patch whatever service "
        "is being exploited, and never run services as root.",
    ),
    Signature(
        "data_exfiltration",
        "Suspected Data Exfiltration",
        r"\b(?:bytes|megabytes|GB|MB) sent to (?:external|unknown)|"
        r"\b(?:exfiltrat\w+|data theft|large outbound transfer|"
        r"transfer to (?:unknown|external) (?:host|server|ip))\b|"
        r"\bcurl\b[^\n]{0,80}(?:-d\s|--data(?:-binary|-raw)?|-T\s|--upload-file)[^\n]{0,80}https?://|"
        r"\bnc\b[^\n]{0,40}-e\s+/bin/(?:ba)?sh",
        "medium",
        "exfiltration",
        "Data that should have stayed inside your network is leaving for an external address. "
        "Exfiltration is usually the payoff stage of an intrusion - the entire reason the attacker "
        "got in was to reach these files, so containment has to happen now.",
        "Block the destination, capture a traffic sample before tearing it down, and audit which "
        "data that account could reach in the hours before the transfer.",
    ),
    Signature(
        "web_shell",
        "Web Shell / Remote Code Execution via Web Request",
        r"\b(?:webshell|web shell|r57|c99|b374k|WSO)\b|"
        r"\b(?:c99|r57|shell)\.php\b|"
        r"\bbase64_decode\s*\(\s*base64_decode|eval\s*\(\s*\$_?(?:POST|GET|REQUEST)",
        "critical",
        "remote_code_execution",
        "Someone is uploading or calling a web shell: a script that gives them a full command "
        "line on your server through an ordinary HTTP request. Once this works, the machine is "
        "lost - the attacker has a shell with whatever privileges your web server runs as, and "
        "usually immediately pivots to persistence.",
        "Isolate the host, find and delete the shell but preserve a copy for forensics, rotate "
        "every credential that lived on that box, and rebuild it. Patch the upload vulnerability "
        "that allowed it.",
    ),
]

SIGNATURE_INDEX = {sig.key: sig for sig in SIGNATURES}


class IOCExtractor:
    """Pull indicators of compromise out of raw text, preserving order."""

    def get_ips(self, text: str) -> list[str]:
        return list(dict.fromkeys(IPV4_REGEX.findall(text)))

    def get_urls(self, text: str) -> list[str]:
        cleaned = (m.rstrip(".,;:!?)]}'\"") for m in URL_REGEX.findall(text))
        return list(dict.fromkeys(u for u in cleaned if u))

    def get_emails(self, text: str) -> list[str]:
        return list(dict.fromkeys(EMAIL_REGEX.findall(text)))

    def get_wallets(self, text: str) -> list[str]:
        return list(dict.fromkeys(WALLET_REGEX.findall(text)))

    def get_domains(self, text: str) -> list[str]:
        hosts: list[str] = []
        for url in self.get_urls(text):
            host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].strip()
            if host:
                hosts.append(host)
        for domain in DOMAIN_REGEX.findall(text):
            if domain not in hosts:
                hosts.append(domain.lower())
        return list(dict.fromkeys(hosts))

    def extract(self, text: str) -> dict[str, list[str]]:
        return {
            "ips": self.get_ips(text),
            "urls": self.get_urls(text),
            "emails": self.get_emails(text),
            "wallets": self.get_wallets(text),
            "domains": self.get_domains(text),
        }


class Detector:
    """Runs every signature over the text and ranks the matches by severity."""

    def __init__(self, signatures: list[Signature] | None = None) -> None:
        self.signatures = signatures if signatures is not None else SIGNATURES

    def analyze(self, text: str) -> dict[str, Any]:
        """Return matches sorted by descending severity."""
        matches: list[dict[str, Any]] = []
        for signature in self.signatures:
            hits = signature.regex.findall(text)
            if hits:
                matches.append(signature.to_dict(hits))

        matches.sort(key=lambda m: severity_rank(m["severity"]), reverse=True)

        signal_count = 0
        for match in matches:
            signal_count += match["matches_found"]

        if not matches:
            verdict, label, severity = "clean", "No threats detected", "info"
        else:
            severity = matches[0]["severity"]
            if severity == "critical":
                verdict, label = "malicious", "Malicious activity detected"
            else:
                verdict, label = "suspicious", "Suspicious activity detected"

        return {
            "verdict": verdict,
            "verdict_label": label,
            "top_severity": severity,
            "match_count": len(matches),
            "signal_count": signal_count,
            "matches": matches,
        }