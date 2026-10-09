"""Turns detections plus IOC context into copy-paste remediation commands."""

from typing import Any

BLOCKABLE_KEYS = {
    "ssh_brute_force",
    "port_scan",
    "privilege_escalation",
    "malware_c2_callback",
    "data_exfiltration",
    "sql_injection",
    "cloud_credential_abuse",
    "web_shell",
}

DOMAIN_BLOCKABLE_KEYS = {"phishing_indicators", "malware_c2_callback", "data_exfiltration", "web_shell"}


def _hosts_from_urls(urls: list[str]) -> list[str]:
    hosts: list[str] = []
    for url in urls:
        host = url.split("//", 1)[-1].split("/", 1)[0].strip()
        if host and host not in hosts:
            hosts.append(host)
    return hosts


class RemediationBuilder:
    """Builds an ordered list of block commands for the highest-severity finding."""

    def build(
        self,
        analysis: dict[str, Any],
        iocs: dict[str, list[str]],
        reputation: dict[str, Any],
    ) -> dict[str, Any]:
        matches = analysis.get("matches", [])
        if not matches:
            return {
                "primary": None,
                "variants": [],
                "note": "No attack signatures matched, so there is nothing to block. If you "
                "expected an alert, paste more surrounding log lines or the full message headers.",
            }

        top = matches[0]
        key = top["key"]
        ips = [i for i in iocs.get("ips", []) if i]
        urls = [u for u in iocs.get("urls", []) if u]
        variants: list[dict[str, Any]] = []

        if ips and key in BLOCKABLE_KEYS:
            ip_list = " ".join(ips)
            variants.append({"tool": "UFW", "os": "Linux", "command": f"sudo ufw deny from {ip_list}"})
            variants.append(
                {"tool": "iptables", "os": "Linux", "command": f"sudo iptables -I INPUT 1 -s {ip_list} -j DROP"}
            )
            variants.append(
                {
                    "tool": "nftables",
                    "os": "Linux",
                    "command": f"sudo nft add rule inet filter input ip saddr {{ {' '.join(ips)} }} drop",
                }
            )
            variants.append(
                {
                    "tool": "Windows Firewall",
                    "os": "Windows",
                    "command": 'netsh advfirewall firewall add rule name="SecurBuddy Block" dir=in '
                    f"action=block remoteip={ip_list}",
                }
            )
            if key == "ssh_brute_force":
                variants.append(
                    {
                        "tool": "fail2ban",
                        "os": "Linux",
                        "command": f"sudo fail2ban-client set sshd banip {ip_list}",
                    }
                )
                variants.append(
                    {
                        "tool": "fail2ban (permanent)",
                        "os": "Linux",
                        "command": "printf '[sshd]\\nenabled = true\\nmaxretry = 5\\nfindtime = 10m\\nbantime = 24h\\n"
                        "port = ssh\\n' | sudo tee /etc/fail2ban/jail.d/securbuddy.local",
                    }
                )

        if urls and key in DOMAIN_BLOCKABLE_KEYS:
            hosts = _hosts_from_urls(urls)
            host_list = " ".join(hosts)
            variants.append(
                {
                    "tool": "/etc/hosts",
                    "os": "Linux / macOS",
                    "command": f'echo "0.0.0.0 {host_list}" | sudo tee -a /etc/hosts',
                }
            )
            variants.append(
                {
                    "tool": "Windows Firewall",
                    "os": "Windows",
                    "command": 'netsh advfirewall firewall add rule name="SecurBuddy Block Domain" dir=out '
                    f"action=block remoteip={host_list}",
                }
            )
            variants.append(
                {
                    "tool": "pf",
                    "os": "macOS",
                    "command": f'echo "block out {host_list}" | sudo pfctl -a securbuddy -e -',
                }
            )

        if key == "ransomware_note":
            variants = [
                {
                    "tool": "Isolate immediately",
                    "os": "Linux",
                    "command": "sudo systemctl isolate multi-user.target   # cut the host off the network",
                },
                {
                    "tool": "Block the payment wallet",
                    "os": "Linux",
                    "command": "# Add the wallet from the note to your exchange's compliance report; "
                    "do NOT pay it.",
                },
            ]
            wallets = iocs.get("wallets", [])
            if wallets:
                variants[1]["command"] = (
                    f"echo \"Ransom wallet: {' '.join(wallets)}\" | sudo tee -a /var/log/ransomware-iocs.txt"
                )

        if key == "sql_injection":
            variants = [
                {
                    "tool": "Block the attacker",
                    "os": "Linux",
                    "command": f"sudo ufw deny from {ips[0]}" if ips else "# no source IP found in the log line",
                },
                {
                    "tool": "Find every injection attempt",
                    "os": "Linux",
                    "command": "grep -Ei \"(OR|UNION)[^\\n]{0,40}(SELECT|1)=(1|SLEEP)\" /var/log/nginx/access.log*",
                },
                {
                    "tool": "Temporary WAF rule (ModSecurity)",
                    "os": "Linux",
                    "command": 'sudo sed -i "s|SecRuleEngine DetectionOnly|SecRuleEngine On|" '
                    "/etc/modsecurity/modsecurity.conf && sudo systemctl reload nginx",
                },
            ]

        if key == "bec_whaling":
            variants = [
                {
                    "tool": "Report the sender domain",
                    "os": "any",
                    "command": "whois -h whois.verisign-grs.com "
                    f"{_hosts_from_urls(urls)[0] if _hosts_from_urls(urls) else 'sender-domain.example'}"
                    " | grep -iE 'registrar|creation|expiry'",
                },
                {
                    "tool": "Quarantine the message",
                    "os": "Microsoft 365",
                    "command": "New-ComplianceCase -CaseType \"IrremediableMessages\" -Status Active",
                },
            ]

        if key == "cloud_credential_abuse":
            variants = [
                {
                    "tool": "Audit the principal's activity",
                    "os": "AWS CLI",
                    "command": "aws cloudtrail lookup-events --lookup-attributes "
                    f"AttributeKey=Username,AttributeValue=attacker-session --max-results 50",
                },
                {
                    "tool": "Find and delete rogue access keys",
                    "os": "AWS CLI",
                    "command": "aws iam list-access-keys --status Active",
                },
                {
                    "tool": "Block the source address",
                    "os": "Linux",
                    "command": f"sudo ufw deny from {ips[0]}" if ips else "# no source IP found",
                },
            ]

        if not variants:
            variants.append(
                {
                    "tool": "No automated block",
                    "os": "any",
                    "command": "# Nothing blockable was extracted from this content. "
                    "Handle it as a policy or training issue rather than a network block.",
                }
            )

        severity_note = _severity_note(top, reputation)
        return {
            "primary": variants[0],
            "variants": variants,
            "note": severity_note,
        }


def _severity_note(top: dict[str, Any], reputation: dict[str, Any]) -> str:
    """Warn when the content verdict is high but no feed corroborates it."""
    ips = [r for r in reputation.get("ip_reports", []) if r.get("status") == "ok"]
    reserved = [r for r in reputation.get("ip_reports", []) if r.get("status") == "reserved_range"]

    if reserved and top["severity"] in {"high", "critical"}:
        return "Heads up: the address in this sample is a reserved documentation range, so no public "
        "threat feed can confirm or deny it. The verdict comes from the content pattern alone - which "
        "is the part that matters."
    if not ips and top["severity"] in {"high", "critical"}:
        return "No live feed could corroborate this indicator, so treat the finding as strongly "
        "suggestive rather than confirmed."
    return None