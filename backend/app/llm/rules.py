"""Rule-based vulnerability analyzer that works without any LLM API key.

Provides template-driven descriptions, fix recommendations, and report
narratives for all supported vulnerability types.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Vulnerability templates
# ---------------------------------------------------------------------------

VULN_TEMPLATES: dict[str, dict[str, Any]] = {
    "sqli": {
        "label": "SQL Injection",
        "severity": "critical",
        "description": (
            "SQL Injection occurs when user-supplied input is incorporated "
            "into a SQL query without proper sanitisation, allowing an "
            "attacker to manipulate the query logic.  This can lead to "
            "unauthorised data access, data modification, or complete "
            "database compromise."
        ),
        "impact": (
            "An attacker can read, modify, or delete arbitrary data in the "
            "database, bypass authentication, and in some cases execute "
            "operating-system commands on the database server."
        ),
        "fix_steps": [
            "Use parameterised queries (prepared statements) for all database access.",
            "Apply an ORM layer that automatically handles parameter binding.",
            "Validate and sanitise all user input against a strict allowlist.",
            "Apply the principle of least privilege to the database account used by the application.",
            "Deploy a Web Application Firewall (WAF) as an additional defence layer.",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    "xss": {
        "label": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "description": (
            "Cross-Site Scripting allows an attacker to inject malicious "
            "scripts into web pages viewed by other users.  The injected "
            "script executes in the victim's browser within the context of "
            "the vulnerable site."
        ),
        "impact": (
            "An attacker can steal session cookies, redirect users to "
            "malicious sites, deface web content, capture keystrokes, or "
            "perform actions on behalf of the victim."
        ),
        "fix_steps": [
            "Encode all output rendered into HTML using context-aware encoding (HTML, JavaScript, URL, CSS).",
            "Implement a strict Content-Security-Policy (CSP) header to limit script sources.",
            "Use modern templating engines that auto-escape output by default.",
            "Validate and sanitise all user-supplied input on the server side.",
            "Set the HttpOnly and Secure flags on session cookies.",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },
    "ssrf": {
        "label": "Server-Side Request Forgery (SSRF)",
        "severity": "high",
        "description": (
            "Server-Side Request Forgery allows an attacker to make the "
            "server issue HTTP requests to arbitrary destinations, including "
            "internal services that are not directly accessible."
        ),
        "impact": (
            "An attacker can access internal services, read cloud metadata "
            "endpoints (e.g. AWS IMDSv1), scan internal networks, or "
            "leverage trust relationships between internal systems."
        ),
        "fix_steps": [
            "Maintain an allowlist of permitted domains and IP ranges for outbound requests.",
            "Block requests to private/reserved IP ranges (10.0.0.0/8, 172.16.0.0/12, 169.254.169.254, etc.).",
            "Disable unnecessary URL schemes (file://, gopher://, dict://).",
            "Use a dedicated egress proxy for server-initiated HTTP requests.",
            "Enforce IMDSv2 on cloud instances to mitigate metadata-based SSRF attacks.",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    },
    "lfi": {
        "label": "Local File Inclusion (LFI)",
        "severity": "high",
        "description": (
            "Local File Inclusion occurs when user input controls a file "
            "path used by the server to include or read files, allowing "
            "an attacker to access arbitrary files on the filesystem."
        ),
        "impact": (
            "An attacker can read sensitive configuration files (e.g. "
            "/etc/passwd, .env), application source code, or log files.  "
            "Combined with log poisoning or other techniques this can "
            "escalate to remote code execution."
        ),
        "fix_steps": [
            "Never use user input directly in file path operations.",
            "Maintain an allowlist of permitted file names or identifiers.",
            "Use a chroot or containerised filesystem to limit accessible paths.",
            "Canonicalise and validate paths, rejecting any containing '../' sequences.",
            "Set restrictive file-system permissions on the application's runtime user.",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
            "https://cwe.mitre.org/data/definitions/98.html",
        ],
    },
    "rce": {
        "label": "Remote Code Execution (RCE)",
        "severity": "critical",
        "description": (
            "Remote Code Execution allows an attacker to execute arbitrary "
            "commands or code on the server, typically through unsafe use "
            "of user input in system calls, deserialisation, or template "
            "rendering."
        ),
        "impact": (
            "An attacker gains full control of the server, enabling data "
            "exfiltration, lateral movement within the network, deployment "
            "of backdoors, and complete system compromise."
        ),
        "fix_steps": [
            "Never pass user input to system shell commands or eval-like functions.",
            "Use language-native libraries instead of spawning OS processes.",
            "If shell execution is unavoidable, use strict allowlists and parameterised APIs (e.g. subprocess with shell=False).",
            "Implement sandboxing or containerisation to limit the blast radius of any compromise.",
            "Disable dangerous deserialisation features and use safe serialisation formats (JSON).",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/Code_Injection",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
    },
    "open_redirect": {
        "label": "Open Redirect",
        "severity": "medium",
        "description": (
            "An Open Redirect vulnerability allows an attacker to craft a "
            "URL on the trusted domain that redirects the user to an "
            "arbitrary external site."
        ),
        "impact": (
            "An attacker can use the trusted domain to redirect victims to "
            "phishing pages, malware distribution sites, or OAuth token "
            "theft endpoints, lending credibility to the malicious link."
        ),
        "fix_steps": [
            "Avoid using user-supplied input to determine redirect destinations.",
            "Maintain an allowlist of permitted redirect URLs or domains.",
            "Use indirect reference maps (e.g. numeric identifiers) that map to known safe URLs.",
            "Validate that the redirect target is a relative path on the same origin.",
            "Display an interstitial warning page before redirecting to external sites.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
    },
    "info_disclosure": {
        "label": "Information Disclosure",
        "severity": "low",
        "description": (
            "The application exposes sensitive information such as server "
            "versions, stack traces, internal paths, or debug data that "
            "can assist an attacker in planning further attacks."
        ),
        "impact": (
            "Disclosed information reduces the effort required for "
            "targeted attacks by revealing software versions, framework "
            "details, or internal architecture."
        ),
        "fix_steps": [
            "Disable verbose error messages and stack traces in production.",
            "Remove server version headers (Server, X-Powered-By, X-AspNet-Version).",
            "Ensure debug mode is disabled in all production deployments.",
            "Implement custom error pages that do not leak technical details.",
            "Review responses for inadvertent exposure of internal paths or credentials.",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    },
    "misconfig": {
        "label": "Security Misconfiguration",
        "severity": "medium",
        "description": (
            "The application or its infrastructure is configured in a way "
            "that introduces security weaknesses, such as default "
            "credentials, unnecessary services, or overly permissive access "
            "controls."
        ),
        "impact": (
            "Misconfigurations can expose administrative interfaces, allow "
            "unauthorised access, or provide an easy path to deeper "
            "compromise of the application or its hosting environment."
        ),
        "fix_steps": [
            "Establish a hardened baseline configuration for all servers and frameworks.",
            "Remove or disable default accounts, sample applications, and unnecessary features.",
            "Automate configuration audits and integrate them into the CI/CD pipeline.",
            "Apply the principle of least privilege to all services and accounts.",
            "Regularly review and update configurations against vendor security guides.",
        ],
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cwe.mitre.org/data/definitions/16.html",
        ],
    },
    "csrf": {
        "label": "Cross-Site Request Forgery (CSRF)",
        "severity": "medium",
        "description": (
            "Cross-Site Request Forgery forces an authenticated user's "
            "browser to send forged requests to the vulnerable application, "
            "performing state-changing actions without the user's knowledge."
        ),
        "impact": (
            "An attacker can change the victim's email, password, or other "
            "account settings, initiate transactions, or perform any action "
            "the victim is authorised to perform."
        ),
        "fix_steps": [
            "Implement anti-CSRF tokens (synchroniser token pattern) on all state-changing requests.",
            "Set the SameSite attribute on session cookies to 'Lax' or 'Strict'.",
            "Verify the Origin and Referer headers on sensitive endpoints.",
            "Require re-authentication for critical actions (e.g. password change).",
            "Use frameworks that provide built-in CSRF protection and ensure it is enabled.",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/csrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/352.html",
        ],
    },
    "idor": {
        "label": "Insecure Direct Object Reference (IDOR)",
        "severity": "high",
        "description": (
            "Insecure Direct Object References occur when an application "
            "uses user-supplied input to access objects (e.g. database "
            "records, files) without verifying the user's authorisation."
        ),
        "impact": (
            "An attacker can access, modify, or delete other users' data "
            "by manipulating object identifiers such as IDs, filenames, or "
            "database keys in API calls."
        ),
        "fix_steps": [
            "Implement server-side authorisation checks for every object access.",
            "Use indirect reference maps instead of exposing internal identifiers.",
            "Replace sequential integer IDs with UUIDs to reduce predictability (defence in depth).",
            "Log and alert on access-control violations for early detection.",
            "Write automated integration tests that verify cross-user access is denied.",
        ],
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/639.html",
        ],
    },
    "xxe": {
        "label": "XML External Entity (XXE) Injection",
        "severity": "high",
        "description": (
            "XXE Injection exploits XML parsers that process external "
            "entity declarations, allowing an attacker to read local "
            "files, perform SSRF, or cause denial of service."
        ),
        "impact": (
            "An attacker can read sensitive files from the server, probe "
            "internal networks, exfiltrate data via out-of-band channels, "
            "or exhaust server resources with recursive entity expansion."
        ),
        "fix_steps": [
            "Disable external entity and DTD processing in all XML parsers.",
            "Use less complex data formats such as JSON where possible.",
            "Validate and sanitise all XML input against a strict schema.",
            "Keep XML parsing libraries up to date with security patches.",
            "If DTD processing is required, use local-only entity resolution.",
        ],
        "references": [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
    },
    "broken_auth": {
        "label": "Broken Authentication",
        "severity": "critical",
        "description": (
            "Broken Authentication encompasses flaws in session management "
            "or credential handling that allow attackers to compromise "
            "passwords, tokens, or session identifiers."
        ),
        "impact": (
            "An attacker can impersonate legitimate users, access "
            "administrative accounts, and take full control of the "
            "application and its data."
        ),
        "fix_steps": [
            "Implement multi-factor authentication (MFA) for all user-facing accounts.",
            "Enforce strong password policies and check against breached-password databases.",
            "Use secure, server-side session management with cryptographically random session IDs.",
            "Implement account lockout or rate limiting after repeated failed login attempts.",
            "Set session timeouts and invalidate sessions on logout and password change.",
        ],
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/287.html",
        ],
    },
    "security_headers": {
        "label": "Missing or Misconfigured Security Headers",
        "severity": "low",
        "description": (
            "The application is missing recommended HTTP security headers "
            "that instruct the browser to enable built-in defence "
            "mechanisms against common attacks."
        ),
        "impact": (
            "Without security headers the application is more susceptible "
            "to attacks such as XSS, clickjacking, MIME-type sniffing, "
            "and protocol downgrade attacks."
        ),
        "fix_steps": [
            "Add Content-Security-Policy header with a restrictive policy.",
            "Add Strict-Transport-Security (HSTS) with a long max-age and includeSubDomains.",
            "Add X-Content-Type-Options: nosniff.",
            "Add X-Frame-Options: DENY (or SAMEORIGIN if framing is needed).",
            "Add Referrer-Policy: strict-origin-when-cross-origin.",
            "Add Permissions-Policy to restrict browser feature access.",
        ],
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security",
        ],
    },
    "ssl_tls": {
        "label": "SSL/TLS Configuration Issue",
        "severity": "medium",
        "description": (
            "The server's SSL/TLS configuration supports weak protocols, "
            "cipher suites, or has certificate issues that undermine the "
            "confidentiality and integrity of encrypted communications."
        ),
        "impact": (
            "An attacker on the network path can intercept or tamper with "
            "encrypted traffic through protocol downgrade attacks, or "
            "exploit weak cipher suites to decrypt communications."
        ),
        "fix_steps": [
            "Disable SSLv3, TLS 1.0, and TLS 1.1; support only TLS 1.2 and TLS 1.3.",
            "Use strong cipher suites with forward secrecy (ECDHE) and disable weak ciphers (RC4, 3DES, NULL).",
            "Ensure certificates are valid, not expired, and issued by a trusted CA.",
            "Enable HSTS to prevent protocol downgrade attacks.",
            "Use tools like SSL Labs to regularly audit TLS configuration.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            "https://www.ssllabs.com/ssltest/",
            "https://cwe.mitre.org/data/definitions/326.html",
        ],
    },
    "cors": {
        "label": "Cross-Origin Resource Sharing (CORS) Misconfiguration",
        "severity": "medium",
        "description": (
            "The application's CORS policy is overly permissive, reflecting "
            "arbitrary origins or allowing credentials with wildcard "
            "origins, which can be exploited to make authenticated "
            "cross-origin requests."
        ),
        "impact": (
            "An attacker can read sensitive data from the API on behalf of "
            "an authenticated user by hosting a malicious page that issues "
            "cross-origin requests to the vulnerable endpoint."
        ),
        "fix_steps": [
            "Restrict Access-Control-Allow-Origin to a strict allowlist of trusted origins.",
            "Never reflect the request Origin header verbatim into the response.",
            "Avoid using Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
            "Limit Access-Control-Allow-Methods and Access-Control-Allow-Headers to only what is needed.",
            "Validate the Origin header on the server side before returning CORS headers.",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
            "https://portswigger.net/web-security/cors",
            "https://cwe.mitre.org/data/definitions/942.html",
        ],
    },
    "clickjacking": {
        "label": "Clickjacking",
        "severity": "medium",
        "description": (
            "The application can be embedded in an iframe on a malicious "
            "site, enabling clickjacking attacks where the user is tricked "
            "into clicking hidden elements on the framed page."
        ),
        "impact": (
            "An attacker can trick users into performing unintended actions "
            "such as changing settings, transferring funds, or granting "
            "permissions by overlaying invisible frames."
        ),
        "fix_steps": [
            "Set the X-Frame-Options header to DENY or SAMEORIGIN.",
            "Use the Content-Security-Policy frame-ancestors directive for finer control.",
            "Implement frame-busting JavaScript as a fallback for legacy browsers.",
            "Require user interaction (e.g. CAPTCHA, re-authentication) for sensitive actions.",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/Clickjacking",
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/1021.html",
        ],
    },
}

# Map common aliases to canonical keys
_ALIASES: dict[str, str] = {
    "sql_injection": "sqli",
    "sql-injection": "sqli",
    "cross_site_scripting": "xss",
    "cross-site-scripting": "xss",
    "server_side_request_forgery": "ssrf",
    "local_file_inclusion": "lfi",
    "remote_code_execution": "rce",
    "command_injection": "rce",
    "open-redirect": "open_redirect",
    "information_disclosure": "info_disclosure",
    "information-disclosure": "info_disclosure",
    "misconfiguration": "misconfig",
    "security_misconfiguration": "misconfig",
    "cross_site_request_forgery": "csrf",
    "insecure_direct_object_reference": "idor",
    "xml_external_entity": "xxe",
    "broken_authentication": "broken_auth",
    "missing_security_headers": "security_headers",
    "security-headers": "security_headers",
    "ssl": "ssl_tls",
    "tls": "ssl_tls",
    "ssl-tls": "ssl_tls",
    "cors_misconfiguration": "cors",
    "cors-misconfiguration": "cors",
}


def _normalise_type(vuln_type: str) -> str:
    """Normalise a vulnerability type string to a canonical template key."""
    key = vuln_type.strip().lower()
    return _ALIASES.get(key, key)


def _get_template(vuln_type: str) -> dict[str, Any]:
    """Return the matching template, or a sensible generic fallback."""
    key = _normalise_type(vuln_type)
    if key in VULN_TEMPLATES:
        return VULN_TEMPLATES[key]
    return {
        "label": vuln_type.replace("_", " ").title(),
        "severity": "medium",
        "description": (
            f"A {vuln_type.replace('_', ' ')} vulnerability was detected. "
            "Review the evidence and remediate according to industry best practices."
        ),
        "impact": (
            "The impact depends on the specific vulnerability context. "
            "Consult the evidence and references for a detailed assessment."
        ),
        "fix_steps": [
            "Review the finding evidence and confirm the vulnerability.",
            "Consult OWASP guidance for the specific vulnerability class.",
            "Apply the recommended fix and verify with a re-scan.",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    }


# ---------------------------------------------------------------------------
# RuleBasedAnalyzer
# ---------------------------------------------------------------------------

class RuleBasedAnalyzer:
    """Template-driven vulnerability analysis that requires no LLM API key.

    This class mirrors the :class:`LLMProvider` interface (minus the async)
    so it can serve as a drop-in local fallback.
    """

    def generate_fix(self, finding: dict) -> str:
        """Return a Markdown-formatted fix recommendation for *finding*."""
        tmpl = _get_template(finding.get("type", "unknown"))
        url = finding.get("url", "N/A")
        param = finding.get("parameter", "N/A")

        lines = [
            f"## Remediation: {tmpl['label']}",
            "",
            f"**Affected URL:** `{url}`  ",
            f"**Parameter:** `{param}`  ",
            f"**Severity:** {tmpl['severity'].upper()}",
            "",
            "### Steps",
            "",
        ]
        for i, step in enumerate(tmpl["fix_steps"], 1):
            lines.append(f"{i}. {step}")

        if tmpl.get("references"):
            lines.append("")
            lines.append("### References")
            lines.append("")
            for ref in tmpl["references"]:
                lines.append(f"- <{ref}>")

        return "\n".join(lines)

    def generate_executive_summary(self, scan_data: dict) -> str:
        """Return a template-based executive summary for *scan_data*."""
        target = scan_data.get("target_url", "the target application")
        total = scan_data.get("total", 0)
        critical = scan_data.get("critical", 0)
        high = scan_data.get("high", 0)
        medium = scan_data.get("medium", 0)
        low = scan_data.get("low", 0)
        info = scan_data.get("info", 0)
        scan_date = scan_data.get("scan_date", "N/A")
        duration = scan_data.get("duration", "N/A")

        # Determine overall risk posture
        if critical > 0:
            posture = "CRITICAL"
            posture_text = (
                "The assessment identified critical vulnerabilities that pose "
                "an immediate and severe risk to the confidentiality, integrity, "
                "and availability of the application and its data. Immediate "
                "remediation is strongly recommended."
            )
        elif high > 0:
            posture = "HIGH"
            posture_text = (
                "The assessment identified high-severity vulnerabilities that "
                "could be exploited to cause significant damage. Prompt "
                "remediation is recommended."
            )
        elif medium > 0:
            posture = "MODERATE"
            posture_text = (
                "The assessment identified medium-severity vulnerabilities "
                "that should be addressed in the near term to reduce the "
                "application's attack surface."
            )
        elif low > 0 or info > 0:
            posture = "LOW"
            posture_text = (
                "The assessment identified only low-severity or informational "
                "findings. While not immediately exploitable, these should be "
                "addressed as part of ongoing security hardening."
            )
        else:
            posture = "CLEAN"
            posture_text = (
                "No vulnerabilities were identified during this assessment. "
                "Continue regular security testing to maintain this posture."
            )

        return "\n".join([
            "## Executive Summary",
            "",
            f"A security assessment was conducted against **{target}** "
            f"on {scan_date} (duration: {duration}).",
            "",
            f"**Overall Risk Posture: {posture}**",
            "",
            posture_text,
            "",
            "### Findings Overview",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| Critical | {critical} |",
            f"| High     | {high} |",
            f"| Medium   | {medium} |",
            f"| Low      | {low} |",
            f"| Info     | {info} |",
            f"| **Total** | **{total}** |",
            "",
            "### Recommendations",
            "",
            "1. Address all critical and high-severity findings immediately.",
            "2. Schedule remediation for medium-severity findings within 30 days.",
            "3. Review low-severity and informational findings during the next development cycle.",
            "4. Conduct a follow-up assessment after remediation to verify fixes.",
        ])

    def generate_report_narrative(self, findings: list[dict]) -> str:
        """Return a Markdown narrative covering all *findings*."""
        if not findings:
            return (
                "## Detailed Findings\n\n"
                "No vulnerabilities were identified during this assessment."
            )

        sections: list[str] = ["## Detailed Findings", ""]

        for i, finding in enumerate(findings, 1):
            tmpl = _get_template(finding.get("type", "unknown"))
            title = finding.get("title", tmpl["label"])
            severity = finding.get("severity", tmpl["severity"]).upper()
            url = finding.get("url", "N/A")
            param = finding.get("parameter", "")
            evidence = finding.get("evidence", "")
            cwe = finding.get("cwe", "")

            sections.append(f"### {i}. {title}")
            sections.append("")
            sections.append(f"**Severity:** {severity}  ")
            sections.append(f"**URL:** `{url}`  ")
            if param:
                sections.append(f"**Parameter:** `{param}`  ")
            if cwe:
                sections.append(f"**CWE:** {cwe}  ")
            sections.append("")

            sections.append("#### Description")
            sections.append("")
            sections.append(tmpl["description"])
            sections.append("")

            if evidence:
                sections.append("#### Evidence")
                sections.append("")
                sections.append(f"```\n{evidence[:1000]}\n```")
                sections.append("")

            sections.append("#### Impact")
            sections.append("")
            sections.append(tmpl["impact"])
            sections.append("")

            sections.append("#### Remediation")
            sections.append("")
            for j, step in enumerate(tmpl["fix_steps"], 1):
                sections.append(f"{j}. {step}")
            sections.append("")

            if tmpl.get("references"):
                sections.append("#### References")
                sections.append("")
                for ref in tmpl["references"]:
                    sections.append(f"- <{ref}>")
                sections.append("")

            sections.append("---")
            sections.append("")

        return "\n".join(sections)
