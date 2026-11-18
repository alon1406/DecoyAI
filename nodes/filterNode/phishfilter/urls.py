"""URL normalization.

The same function MUST be used by the update job (when storing feed entries)
and by the Filter (when checking an email). Otherwise matches are missed.

normalize_url("https://WWW.Evil.com:8080/Login/?utm=1#x") -> "evil.com/Login"
"""
from urllib.parse import urlparse, parse_qs, unquote

import tldextract

MAX_UNWRAP_DEPTH = 3

# Redirect wrappers: (host suffix, required path or None, query params that hold the real URL)
_UNWRAPPERS = [
    ("safelinks.protection.outlook.com", None, ("url",)),
    ("google.com", "/url", ("q", "url")),
]

# Offline extractor: uses the bundled public-suffix snapshot, never the network.
# Private suffixes included, so "x.github.io" is its own registered domain.
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def _unwrap_target(host: str, path: str, query: str) -> str:
    """If the URL is a known redirect wrapper, return the wrapped URL, else ''."""
    for suffix, required_path, params in _UNWRAPPERS:
        if host == suffix or host.endswith("." + suffix):
            if required_path is not None and path != required_path:
                continue
            values = parse_qs(query)
            for name in params:
                if values.get(name):
                    return unquote(values[name][0])
    return ""


def normalize_url(url: str, _depth: int = 0) -> str:
    """Return a canonical 'host/path' form, or '' if the input is unusable."""
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if not url or any(ord(c) < 32 for c in url):
        return ""
    if url.startswith("//"):
        url = "http:" + url
    elif "://" not in url:
        url = "http://" + url

    try:
        p = urlparse(url)
        host = (p.hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""
    if not host:
        return ""

    if _depth < MAX_UNWRAP_DEPTH:
        inner = _unwrap_target(host, p.path, p.query)
        if inner:
            return normalize_url(inner, _depth + 1)

    try:
        host = host.encode("idna").decode("ascii")   # punycode form, like the feeds use
    except UnicodeError:
        pass

    return f"{host}{p.path.rstrip('/')}"


def host_of(normalized: str) -> str:
    """Host part of a normalized 'host/path' value."""
    return normalized.split("/", 1)[0]


def registered_domain(host: str) -> str:
    """'login.secure.evil.co.uk' -> 'evil.co.uk'. For IPs / unknown suffixes returns the host."""
    parts = _extract(host)
    # newer tldextract renamed registered_domain; support both without
    # touching the deprecated name when the new one exists
    if hasattr(parts, "top_domain_under_public_suffix"):
        domain = parts.top_domain_under_public_suffix
    else:
        domain = parts.registered_domain
    return domain or host
