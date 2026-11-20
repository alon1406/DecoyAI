"""Domain normalization.

The same function MUST be used by the update job (when storing feed domains)
and by the Filter (on the Parser's `sender_domain`). Otherwise matches are missed.

normalize_domain("  WWW.Evil.COM. ") -> "evil.com"
normalize_domain("bücher.example")    -> "xn--bcher-kva.example"
normalize_domain("not a domain")      -> ""
"""
import re

MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63

# One DNS label: letters, digits, hyphen (not at the start or end).
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
# Four numbers separated by dots: an IPv4 address, not a domain name.
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normalize_domain(value: str) -> str:
    """Return a canonical lowercase ASCII domain, or '' if the input is unusable.

    Steps: strip spaces, lowercase, remove trailing dots, remove a leading
    "www.", convert international names to punycode, then validate.
    """
    if not isinstance(value, str):
        return ""
    domain = value.strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    if not domain:
        return ""
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(domain) > MAX_DOMAIN_LENGTH or _IPV4.match(domain):
        return ""
    labels = domain.split(".")
    if len(labels) < 2:
        return ""  # a single word such as "localhost" is not a domain we can match
    for label in labels:
        if len(label) > MAX_LABEL_LENGTH or not _LABEL.match(label):
            return ""
    return domain
