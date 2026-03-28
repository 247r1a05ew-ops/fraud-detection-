import re
import socket
import ssl
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone

try:
    import whois
except ImportError:
    whois = None


SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"
}


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def is_ip_address(hostname):
    try:
        socket.inet_aton(hostname.split(":")[0])
        return True
    except:
        return False


def is_url_shortener(hostname):
    hostname = hostname.replace("www.", "")
    return hostname in SHORTENERS


def has_repeated_chars(hostname):
    return bool(re.search(r"(.)\1\1", hostname))  # 3 repeated chars


def has_valid_ssl(url):
    try:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0]

        if parsed.scheme != "https":
            return False

        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except:
        return False


def check_domain_age(hostname):
    if whois is None:
        return None

    try:
        hostname = hostname.replace("www.", "")
        info = whois.whois(hostname)
        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return None

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age = (datetime.now(timezone.utc) - creation_date).days
        return age
    except:
        return None


def check_reachable(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return True, response.status_code
    except:
        return False, 0