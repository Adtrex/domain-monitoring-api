import re
from typing import Optional

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


DEFAULT_LINK = None  # Will be generated dynamically as a Google search

KEYWORD_LINKS = [
    ("dnssec", "https://www.icann.org/resources/pages/dnssec-what-is-it-2019-03-05-en"),
    ("subdomain takeover", "https://owasp.org/www-community/vulnerabilities/Subdomain_Takeover"),
    ("caa", "https://datatracker.ietf.org/doc/html/rfc8659"),
    ("tls", "https://ssl-config.mozilla.org/"),
    ("ssl", "https://www.ssllabs.com/ssltest/"),
    ("cipher", "https://www.rfc-editor.org/rfc/rfc9325"),
    ("hsts", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"),
    ("content-security-policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"),
    ("x-frame-options", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"),
    ("x-content-type-options", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    ("permissions-policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"),
    ("xss", "https://owasp.org/www-community/attacks/xss/"),
    ("prototype pollution", "https://owasp.org/www-community/attacks/Prototype_Pollution"),
    ("jquery", "https://owasp.org/www-community/attacks/xss/"),
    ("swiper", "https://owasp.org/www-community/attacks/Prototype_Pollution"),
    ("spf", "https://datatracker.ietf.org/doc/html/rfc7208"),
    ("dkim", "https://datatracker.ietf.org/doc/html/rfc6376"),
    ("dmarc", "https://datatracker.ietf.org/doc/html/rfc7489"),
    ("open redirect", "https://owasp.org/www-community/attacks/Redirect"),
    ("directory listing", "https://owasp.org/www-community/attacks/Directory_Listing"),
    ("clickjacking", "https://owasp.org/www-community/attacks/Clickjacking"),
    ("csrf", "https://owasp.org/www-community/attacks/csrf/"),
    ("xxe", "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"),
    ("sqli", "https://owasp.org/www-community/attacks/SQL_Injection"),
    ("sql injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
    ("ssrf", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"),
    ("server-side request forgery", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"),
    ("lfi", "https://owasp.org/www-community/attacks/Local_File_Inclusion"),
    ("local file inclusion", "https://owasp.org/www-community/attacks/Local_File_Inclusion"),
    ("rfi", "https://owasp.org/www-community/attacks/Remote_File_Inclusion"),
    ("remote file inclusion", "https://owasp.org/www-community/attacks/Remote_File_Inclusion"),
    ("xxs", "https://owasp.org/www-community/attacks/xss/"),
    ("deserialization", "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"),
    ("exposed admin", "https://owasp.org/www-community/attacks/Exposed_Admin_Interfaces"),
    ("directory traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
    ("path traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
    ("insecure cookie", "https://owasp.org/www-community/controls/Session_Management"),
    ("weak password", "https://owasp.org/www-community/vulnerabilities/Weak_Password_Requirements"),
    ("exposed credentials", "https://owasp.org/www-community/vulnerabilities/Exposed_Credentials"),
    ("exposed api key", "https://owasp.org/www-community/vulnerabilities/Exposed_Credentials"),
    ("exposed token", "https://owasp.org/www-community/vulnerabilities/Exposed_Credentials"),
    ("directory index", "https://owasp.org/www-community/attacks/Directory_Listing"),
    ("open port", "https://www.acunetix.com/blog/articles/open-ports/"),
    ("ftp", "https://www.acunetix.com/blog/articles/ftp-security/"),
    ("telnet", "https://www.acunetix.com/blog/articles/telnet-security/"),
    ("smb", "https://www.acunetix.com/blog/articles/smb-security/"),
    ("rdp", "https://www.acunetix.com/blog/articles/rdp-security/"),
    ("exposed git", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("exposed .git", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("exposed env", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("exposed .env", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("exposed backup", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("backup file", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("directory browsing", "https://owasp.org/www-community/attacks/Directory_Listing"),
    ("exposed admin", "https://owasp.org/www-community/attacks/Exposed_Admin_Interfaces"),
    ("exposed dashboard", "https://owasp.org/www-community/attacks/Exposed_Admin_Interfaces"),
    ("exposed panel", "https://owasp.org/www-community/attacks/Exposed_Admin_Interfaces"),
    ("exposed login", "https://owasp.org/www-community/attacks/Exposed_Admin_Interfaces"),
    ("exposed database", "https://owasp.org/www-community/attacks/Exposed_Database_Interfaces"),
    ("exposed phpinfo", "https://owasp.org/www-community/attacks/Exposed_PHP_Configuration"),
    ("exposed config", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("exposed configuration", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("exposed source", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("exposed code", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("exposed file", "https://owasp.org/www-community/attacks/Source_Code_Disclosure"),
    ("exposed directory", "https://owasp.org/www-community/attacks/Directory_Listing"),
    ("exposed folder", "https://owasp.org/www-community/attacks/Directory_Listing"),
    ("exposed bucket", "https://owasp.org/www-community/attacks/Exposed_Cloud_Storage"),
    ("cloud bucket", "https://owasp.org/www-community/attacks/Exposed_Cloud_Storage"),
    ("s3 bucket", "https://owasp.org/www-community/attacks/Exposed_Cloud_Storage"),
    ("misconfiguration", "https://owasp.org/www-community/attacks/Misconfiguration"),
    ("insecure deserialization", "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"),
    ("exposed elasticsearch", "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html"),
    ("exposed kibana", "https://www.elastic.co/guide/en/kibana/current/security-settings-kb.html"),
    ("exposed grafana", "https://grafana.com/docs/grafana/latest/security/"),
    ("exposed prometheus", "https://prometheus.io/docs/prometheus/latest/security/"),
    ("exposed rabbitmq", "https://www.rabbitmq.com/security.html"),
    ("exposed redis", "https://redis.io/topics/security"),
    ("exposed mongodb", "https://www.mongodb.com/docs/manual/administration/security-checklist/"),
    ("exposed mysql", "https://dev.mysql.com/doc/refman/8.0/en/security.html"),
    ("exposed postgres", "https://www.postgresql.org/docs/current/security.html"),
    ("exposed database", "https://owasp.org/www-community/attacks/Exposed_Database_Interfaces"),
    ("exposed docker", "https://docs.docker.com/engine/security/"),
    ("exposed kubernetes", "https://kubernetes.io/docs/concepts/security/overview/"),
    ("exposed jenkins", "https://www.jenkins.io/doc/book/security/"),
    ("exposed gitlab", "https://docs.gitlab.com/ee/user/application_security/"),
    ("exposed github", "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure"),
    ("exposed bitbucket", "https://support.atlassian.com/bitbucket-cloud/docs/security-best-practices/"),
    ("exposed svn", "https://subversion.apache.org/security.html"),
    ("exposed mercurial", "https://www.mercurial-scm.org/wiki/Security"),
    ("exposed ftp", "https://www.acunetix.com/blog/articles/ftp-security/"),
    ("exposed telnet", "https://www.acunetix.com/blog/articles/telnet-security/"),
    ("exposed rdp", "https://www.acunetix.com/blog/articles/rdp-security/"),
    ("exposed smb", "https://www.acunetix.com/blog/articles/smb-security/"),
    ("exposed nfs", "https://www.acunetix.com/blog/articles/nfs-security/"),
    ("exposed rsync", "https://www.acunetix.com/blog/articles/rsync-security/"),
    ("exposed memcached", "https://www.acunetix.com/blog/articles/memcached-security/"),
    ("exposed rabbitmq", "https://www.rabbitmq.com/security.html"),
    ("exposed redis", "https://redis.io/topics/security"),
    ("exposed elasticsearch", "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html"),
    ("exposed grafana", "https://grafana.com/docs/grafana/latest/security/"),
    ("exposed prometheus", "https://prometheus.io/docs/prometheus/latest/security/"),
    ("exposed jenkins", "https://www.jenkins.io/doc/book/security/"),
    ("exposed gitlab", "https://docs.gitlab.com/ee/user/application_security/"),
    ("exposed github", "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure"),
    ("exposed bitbucket", "https://support.atlassian.com/bitbucket-cloud/docs/security-best-practices/"),
    ("exposed svn", "https://subversion.apache.org/security.html"),
    ("exposed mercurial", "https://www.mercurial-scm.org/wiki/Security"),
]


def get_external_reference(title: str, detail: str = "") -> str:
    text = f"{title} {detail}".strip()

    cve_match: Optional[re.Match[str]] = CVE_REGEX.search(text)
    if cve_match:
        cve = cve_match.group(0).upper()
        return f"https://nvd.nist.gov/vuln/detail/{cve}"

    lower_text = text.lower()
    for keyword, link in KEYWORD_LINKS:
        if keyword in lower_text:
            return link

    # Default: Google search for the issue
    query = re.sub(r'[^\w\s-]', '', text)
    query = "+".join(query.split())
    return f"https://www.google.com/search?q={query}+security"
