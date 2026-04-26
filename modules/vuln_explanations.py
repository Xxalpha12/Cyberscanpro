"""
Plain English vulnerability explanations for CyberScan Pro reports.
Each entry has: what_it_is, what_it_means, real_world_impact, how_to_fix, severity_why
"""

VULN_EXPLANATIONS = {
    # ── MISSING SECURITY HEADERS ──────────────────────────────────────────────
    "Missing Security Header: X-Frame-Options": {
        "what_it_is": "This website is missing a security instruction that prevents it from being embedded inside another webpage.",
        "what_it_means": "An attacker can create a fake webpage that secretly loads your website inside it (called Clickjacking). When a visitor clicks something on the fake page, they are actually clicking on your website without knowing it — potentially making purchases, changing settings, or approving actions they never intended.",
        "real_world_impact": "Attackers can trick users into clicking 'Delete Account', 'Send Money', or 'Grant Access' buttons on your site without them realizing it.",
        "how_to_fix": "Add this line to your web server configuration:\n  X-Frame-Options: SAMEORIGIN\nThis tells browsers to never allow your site to be loaded inside another site's frame.",
        "difficulty": "Easy — 5 minute fix"
    },
    "Missing Security Header: Content-Security-Policy": {
        "what_it_is": "The website has no Content Security Policy — a set of rules that tells the browser what content is allowed to load on the page.",
        "what_it_means": "Without this, an attacker who finds any vulnerability on your site can inject and run malicious scripts that steal user data, redirect visitors, or hijack sessions.",
        "real_world_impact": "If an attacker injects JavaScript into your page (via XSS), a CSP would block it from running. Without it, the attack succeeds completely — potentially stealing login cookies, credit card numbers, or personal data from every visitor.",
        "how_to_fix": "Add a Content-Security-Policy header to your server responses. Start with:\n  Content-Security-Policy: default-src 'self'\nThis only allows content from your own domain.",
        "difficulty": "Medium — requires testing"
    },
    "Missing Security Header: Strict-Transport-Security": {
        "what_it_is": "The website is not enforcing HTTPS connections for returning visitors.",
        "what_it_means": "Even if your site supports HTTPS, attackers can intercept the first request from a visitor and downgrade it to HTTP (unencrypted). All data sent — including passwords and personal information — can be read.",
        "real_world_impact": "On public Wi-Fi (cafes, airports, hotels), attackers can steal login credentials, session cookies, and sensitive data from your users before they even connect securely.",
        "how_to_fix": "Add this header to your server:\n  Strict-Transport-Security: max-age=31536000; includeSubDomains\nThis tells browsers to always use HTTPS for your site for the next year.",
        "difficulty": "Easy — 5 minute fix"
    },
    "Missing Security Header: X-Content-Type-Options": {
        "what_it_is": "The website is missing a header that prevents browsers from guessing the type of file being served.",
        "what_it_means": "Browsers sometimes 'sniff' file types — if an attacker uploads a file disguised as an image but containing malicious script, the browser might execute it.",
        "real_world_impact": "Attackers can upload malicious files that get executed as scripts, potentially compromising users who view them.",
        "how_to_fix": "Add this header:\n  X-Content-Type-Options: nosniff\nThis tells the browser to trust your declared file types and not guess.",
        "difficulty": "Easy — 2 minute fix"
    },
    "Missing Security Header: X-XSS-Protection": {
        "what_it_is": "The website is missing a legacy browser protection against reflected Cross-Site Scripting attacks.",
        "what_it_means": "Older browsers have a built-in XSS filter that can be activated with this header. Without it, some older browsers won't attempt to block XSS attacks.",
        "real_world_impact": "Users on older browsers (Internet Explorer, older Chrome) are more vulnerable to script injection attacks.",
        "how_to_fix": "Add this header:\n  X-XSS-Protection: 1; mode=block\nNote: Modern browsers rely on CSP instead, but this header helps with older browsers.",
        "difficulty": "Easy — 2 minute fix"
    },
    "Missing Security Header: Referrer-Policy": {
        "what_it_is": "The website does not control what information is shared when users click links to other websites.",
        "what_it_means": "When a user clicks a link that leaves your site, the browser automatically tells the next site where the user came from — including the full URL. This can leak sensitive information like user IDs, session tokens, or private page paths.",
        "real_world_impact": "If a user is on a private page like /account/reset?token=abc123 and clicks an external link, that token gets sent to the external site in the Referer header.",
        "how_to_fix": "Add this header:\n  Referrer-Policy: strict-origin-when-cross-origin",
        "difficulty": "Easy — 2 minute fix"
    },

    # ── WEB APPLICATION VULNERABILITIES ───────────────────────────────────────
    "SQL Injection": {
        "what_it_is": "The website passes user input directly into database queries without checking it first.",
        "what_it_means": "An attacker can type specially crafted text into a form field or URL that manipulates your database. Instead of searching for a username, they can extract all usernames and passwords, delete all records, or take complete control of the database.",
        "real_world_impact": "This is one of the most dangerous vulnerabilities. Attackers can steal your entire database — every user's email, password, personal information, and payment details. They can also delete all your data or log in as any user including administrators.",
        "how_to_fix": "Never build database queries by combining strings with user input. Use parameterized queries or prepared statements instead:\n  WRONG:  query = 'SELECT * FROM users WHERE name = ' + userInput\n  RIGHT:  query = 'SELECT * FROM users WHERE name = ?', [userInput]",
        "difficulty": "Medium — requires code changes"
    },
    "Blind SQL Injection (Time-Based)": {
        "what_it_is": "A more advanced form of SQL injection where the database can be manipulated even when error messages are hidden.",
        "what_it_means": "The attacker cannot see error messages, but they can ask the database true/false questions and measure how long the response takes. By asking thousands of questions, they can extract the entire database character by character.",
        "real_world_impact": "Even with error messages disabled, attackers can slowly extract your entire database. It takes longer but the end result is the same — complete data theft.",
        "how_to_fix": "Same fix as SQL Injection — use parameterized queries. Also consider a Web Application Firewall (WAF) to detect and block unusual query patterns.",
        "difficulty": "Medium — requires code changes"
    },
    "Cross-Site Scripting (XSS)": {
        "what_it_is": "The website displays user-submitted content without checking it for malicious code.",
        "what_it_means": "An attacker can submit JavaScript code through a form, comment, or URL parameter. When other users view that content, the malicious script runs in their browser — as if it came from your website.",
        "real_world_impact": "Attackers can steal session cookies (logging in as the victim), redirect users to fake login pages to steal passwords, make the browser perform actions on behalf of the user (send messages, make purchases), or install malware.",
        "how_to_fix": "Always encode user input before displaying it on a page. Never insert raw user data into HTML:\n  WRONG:  <div>Hello, {username}</div>\n  RIGHT:  <div>Hello, {escape(username)}</div>\nAlso implement a Content-Security-Policy header.",
        "difficulty": "Medium — requires code review"
    },
    "Cross-Site Scripting (XSS) — Form Field": {
        "what_it_is": "A form field on this website accepts and reflects JavaScript code without sanitizing it.",
        "what_it_means": "Attackers can craft a link containing malicious code in a form field. When clicked by a victim, the code runs in their browser with full access to their session on your site.",
        "real_world_impact": "Credential theft, session hijacking, and unauthorized actions performed on behalf of unsuspecting users.",
        "how_to_fix": "Validate and sanitize all form inputs on both the client and server side. Use HTML encoding when displaying user-submitted data.",
        "difficulty": "Medium — requires code review"
    },
    "Directory Traversal": {
        "what_it_is": "The website allows file paths in URLs or parameters, which can be manipulated to access files outside the intended folder.",
        "what_it_means": "By typing ../../etc/passwd or similar in a URL, an attacker can trick the server into reading files it should never expose — like server configuration files, password files, or private documents.",
        "real_world_impact": "Attackers can read sensitive server files including database credentials, API keys, user data files, and system configuration. On some systems, they can read files containing admin passwords.",
        "how_to_fix": "Never use user-supplied input directly in file system paths. Validate that the resolved path starts with your intended base directory:\n  basePath = '/var/www/files/'\n  if not realPath.startswith(basePath): reject()",
        "difficulty": "Medium — requires code changes"
    },
    "Open Redirect": {
        "what_it_is": "The website redirects users to URLs specified in request parameters without validating them.",
        "what_it_means": "Attackers can send users a link to your trusted website that secretly redirects them to a malicious site. Because the link starts with your legitimate domain, users trust it.",
        "real_world_impact": "Phishing attacks become much more convincing. An attacker sends 'Click here to verify your account: yoursite.com/redirect?to=evilsite.com'. The victim trusts your domain, gets redirected to a fake login page, and gives away their password.",
        "how_to_fix": "Never redirect to user-supplied URLs. Use a whitelist of allowed redirect destinations, or only allow relative paths (paths that stay on your own domain).",
        "difficulty": "Easy — requires code change"
    },
    "Sensitive File Exposed": {
        "what_it_is": "A file containing sensitive information is publicly accessible on the web server.",
        "what_it_means": "Files like .env, config.php, backup.zip, or .git folders that should be private are readable by anyone on the internet.",
        "real_world_impact": "These files often contain database passwords, API keys, secret tokens, and server configurations. An attacker who finds them can gain immediate access to your database and all connected services.",
        "how_to_fix": "Move sensitive files outside the web root directory, configure your web server to deny access to configuration files, and never commit .env files to public repositories.",
        "difficulty": "Easy — server configuration change"
    },
    "Missing CSRF Protection": {
        "what_it_is": "Forms on this website do not include a secret token to verify that form submissions come from legitimate users.",
        "what_it_means": "An attacker can create a hidden form on their own website that submits to your website. When a logged-in user visits the attacker's page, their browser automatically submits the form — performing actions on your site without the user's knowledge.",
        "real_world_impact": "If the victim is logged into their bank account and visits a malicious page, that page can silently transfer money. On social platforms, it can post spam. On admin panels, it can create admin accounts for the attacker.",
        "how_to_fix": "Add a CSRF token to every form — a unique secret value that your server generates and checks with each submission:\n  <input type='hidden' name='csrf_token' value='{generate_token()}'>",
        "difficulty": "Medium — requires code changes"
    },

    # ── CVE-BASED FINDINGS ────────────────────────────────────────────────────
    "CVE": {
        "what_it_is": "A known security vulnerability has been identified in the software running on this server.",
        "what_it_means": "This vulnerability has been publicly documented and assigned an official CVE (Common Vulnerabilities and Exposures) number. Security researchers and attackers alike are aware of it.",
        "real_world_impact": "Because the vulnerability is publicly known, automated attack tools actively scan the internet for servers running affected software versions. The server may already be under attack.",
        "how_to_fix": "Update the affected software to the latest patched version immediately. Check the CVE entry at https://nvd.nist.gov for specific patch information and affected versions.",
        "difficulty": "Usually Easy — software update required"
    }
}


def get_explanation(vuln_type: str) -> dict:
    """Get plain English explanation for a vulnerability type."""
    # Direct match
    if vuln_type in VULN_EXPLANATIONS:
        return VULN_EXPLANATIONS[vuln_type]

    # Partial match
    for key, val in VULN_EXPLANATIONS.items():
        if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
            return val

    # CVE fallback
    if vuln_type.startswith("CVE-"):
        return VULN_EXPLANATIONS["CVE"]

    # Generic fallback
    return {
        "what_it_is": f"A security vulnerability of type '{vuln_type}' was detected.",
        "what_it_means": "This vulnerability could potentially be exploited by an attacker to compromise the security of the target system.",
        "real_world_impact": "The impact depends on the specific nature of the vulnerability and the attacker's objectives.",
        "how_to_fix": "Review the evidence provided and consult security documentation for this vulnerability type. Consider engaging a security professional for remediation guidance.",
        "difficulty": "Unknown — security review recommended"
    }
