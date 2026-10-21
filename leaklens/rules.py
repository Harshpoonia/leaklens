"""Detection rules.

Each rule is a regex with exactly one capture group: the secret itself.
Start small and precise. Every rule you add is a false-positive budget you spend.
(Later: move these to YAML so contributors can add providers without touching code.)
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    provider: str
    pattern: re.Pattern[bytes]
    explain: str     # plain-English: what an attacker can do
    rotate_url: str  # where to revoke / regenerate
    # Cheap literal prefilter: the regex only runs if one of these appears.
    # `bytes in bytes` is a fast C search; Python's regex engine can't skip
    # ahead on alternations like (?:AKIA|ASIA) and steps through every byte.
    keywords: tuple[bytes, ...] = ()

    def finditer(self, data: bytes):
        if self.keywords and not any(k in data for k in self.keywords):
            return iter(())
        return self.pattern.finditer(data)


def _rx(p: str) -> re.Pattern[bytes]:
    return re.compile(p.encode())


RULES: list[Rule] = [
    Rule(
        id="google-api-key",
        provider="Google (Gemini / Maps / Firebase)",
        pattern=_rx(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"),
        explain="Anyone can call Google APIs billed to your project, e.g. burn your Gemini quota or run up Maps charges.",
        rotate_url="https://console.cloud.google.com/apis/credentials",
        keywords=(b"AIza",),
    ),
    Rule(
        id="openai-api-key",
        provider="OpenAI",
        pattern=_rx(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,})(?![A-Za-z0-9_\-])"),
        explain="Anyone can make OpenAI API calls charged to your account until the key is revoked.",
        rotate_url="https://platform.openai.com/api-keys",
        keywords=(b"sk-",),
    ),
    Rule(
        id="aws-access-key-id",
        provider="AWS",
        pattern=_rx(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        explain="Combined with its secret key, this can give full control of your AWS account: crypto-mining bills are the classic outcome.",
        rotate_url="https://console.aws.amazon.com/iam/home#/security_credentials",
        keywords=(b"AKIA", b"ASIA"),
    ),
    Rule(
        id="github-token",
        provider="GitHub",
        pattern=_rx(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
        explain="Can read or push to your repositories, including private ones, depending on its scopes.",
        rotate_url="https://github.com/settings/tokens",
        keywords=(b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_", b"github_pat_"),
    ),
    Rule(
        id="stripe-secret-key",
        provider="Stripe",
        pattern=_rx(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"),
        explain="Live Stripe secret: can issue refunds, read customer data and move money.",
        rotate_url="https://dashboard.stripe.com/apikeys",
        keywords=(b"_live_",),
    ),
    Rule(
        id="mongodb-uri",
        provider="MongoDB",
        pattern=_rx(r"(mongodb(?:\+srv)?://[^\s:/@\"']+:[^\s@\"']+@[^\s\"'/]+)"),
        explain="Connection string with a password: anyone can read, change or delete your database.",
        rotate_url="https://cloud.mongodb.com/ (Database Access -> edit user -> new password)",
        keywords=(b"mongodb",),
    ),
    Rule(
        id="private-key",
        provider="Private key (SSH / TLS)",
        pattern=_rx(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)"),
        explain="A private key: can impersonate you or your server.",
        rotate_url="Generate a new keypair and remove the old public key everywhere it is trusted.",
        keywords=(b"PRIVATE KEY-----",),
    ),
]


# ---------------------------------------------------------------------------
# Entropy (opt-in). Only looks at values assigned to secret-ish names, because
# raw entropy over a whole repo flags every hash, UUID and minified bundle.
# ---------------------------------------------------------------------------
ENTROPY_CANDIDATE = _rx(
    r"(?i)(?:secret|token|api_?key|apikey|passwd|password|auth)[\w\-]*\s*[:=]\s*[\"']([A-Za-z0-9+/=_\-]{20,})[\"']"
)
ENTROPY_THRESHOLD = 4.0  # bits per char; tune against real repos


def shannon_entropy(s: bytes) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


# Every prefilter keyword, so a blob can be checked for all of them in one pass.
ALL_KEYWORDS: tuple[bytes, ...] = tuple(sorted({k for r in RULES for k in r.keywords}))
assert all(r.keywords for r in RULES), "every rule needs prefilter keywords"
