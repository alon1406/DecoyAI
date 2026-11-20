"""Domains the Filter never treats as a hit.

These services are used by millions of people. A feed may list one of them by
mistake (or list a sub-domain such as someone.github.io); blocking it would stop
every email from that service without the agents ever looking at it.
Excluded domains are not stored by the update job (Stage 3) and never count as a
hit for the sender domain (Stage 4). Excluded never means "legitimate": the email
simply goes on to the agents.
"""

SHARED_HOSTING = frozenset({
    "github.io", "sites.google.com", "blogspot.com",
    "netlify.app", "vercel.app", "azurewebsites.net",
})

FREE_MAIL = frozenset({
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
})


def is_excluded(domain: str) -> bool:
    """True if domain is, or is under, a shared-hosting or free-mail domain.

    The '.' matters: "x.github.io" is excluded, "fakegmail.com" is not.
    """
    for base in SHARED_HOSTING | FREE_MAIL:
        if domain == base or domain.endswith("." + base):
            return True
    return False
