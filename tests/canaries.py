"""Masking canaries, built at RUNTIME so no realistic token literal ever sits in the repository.

GitHub push protection (and any secret scanner) would flag a real-looking token committed in a test.
Every value below is assembled from harmless fragments when the function is called, and none of them
is valid for any service. `core` is the part that must never survive masking.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass


@dataclass(frozen=True)
class Canary:
    name: str
    core: str  # the secret text that must not appear in any derived output
    line: str  # a source line (or message) that contains it, in the shape a scanner would see


def _rep(fragment: str, times: int) -> str:
    return fragment * times


def single_line_canaries() -> list[Canary]:
    github = "gh" + "p_" + _rep("Zk3Rt9Qm", 5)
    fine = "github" + "_pat_" + "11AB" + _rep("C", 18) + "_" + _rep("Pq7Lx2", 10)
    oauth = "gh" + "o_" + _rep("Wv5Ns1Hd", 5)
    slack = "xo" + "xb-" + _rep("1", 11) + "-" + _rep("2", 12) + "-" + _rep("AbCdEf", 4)
    google = "AI" + "za" + "Sy" + _rep("A1b2C3d4E5", 3) + "xYz"
    openai = "sk" + "-proj-" + _rep("Q9wE3rT7yU1iO5pA", 3)
    anthropic = "sk" + "-ant-api03-" + _rep("Hj4Kl8Zx2Cv6Bn0M", 5)
    akia = "AK" + "IA" + "QWERTYUIOPASDFGH"
    asia = "AS" + "IA" + "ZXCVBNMQWERTYUIO"
    jwt = ".".join(
        ["ey" + "J" + "hbGciOiJIUzI1NiJ9", "ey" + "J" + "zdWIiOiJ0ZXN0In0", "Sig9aB3cD5eF7gH"]
    )
    pg_password = "Tr0ub4dor" + "&3xK"
    token_in_url = "Vb8Nm4Qw2Er6Ty0U"  # noqa: S105 - harmless fragment, not a credential
    bearer = "Mk9Lp3Oj7Ni1Bh5V"
    basic = base64.b64encode(("svc" + ":" + "Rj4Ud8Ie2Yt6").encode()).decode()
    blob = "Pq8Zx3Cv7Bn1Mk5Lj9Hg2Fd6Sa4Tr0Yw3Qe"
    typed = "Hd7Gf3Sa9Kl1Zx5C"
    letters_only = "qwjkhsdfpoiuzxcvbnmasdfghjklqwertyuiop" + "." + "zxcvbnmlkjhgfdsapoiu"
    return [
        Canary("github_classic", github, f'GITHUB_TOKEN = "{github}"'),
        Canary("github_fine_grained", fine, f"export GH={fine}"),
        Canary("github_oauth", oauth, f"headers = ['{oauth}']"),
        Canary("slack_bot", slack, f"SLACK = '{slack}'"),
        Canary("google_api_key", google, f'url = "https://x.example/?key={google}"'),
        Canary("sk_project_key", openai, f'client = Client("{openai}")'),
        Canary("sk_anthropic_style", anthropic, f"KEY={anthropic}"),
        Canary("aws_akia", akia, f"aws_access_key_id = {akia}"),
        Canary("aws_asia", asia, f"# temporary credentials {asia} expire"),
        Canary("jwt", jwt, f'token_value = "{jwt}"'),
        Canary(
            "url_password",
            pg_password,
            f'DSN = "postgres://svc_admin:{pg_password}@db.internal:5432/app"',
        ),
        Canary(
            "url_token",
            token_in_url,
            f"git clone https://x-access-token:{token_in_url}@github.com/org/repo.git",
        ),
        Canary("authorization_bearer", bearer, f"Authorization: Bearer {bearer}"),
        Canary("bearer_in_code", bearer, f'headers = {{"Authorization": "Bearer {bearer}"}}'),
        Canary("authorization_basic", basic, f"Authorization: Basic {basic}"),
        Canary("high_entropy_unnamed", blob, f'session_blob = "{blob}"'),
        Canary("typed_assignment", typed, f'secret_key: str = "{typed}"'),
        Canary("typed_optional_assignment", typed, f'password: Optional[str] = "{typed}"'),
        Canary("dotted_value_for_sensitive_key", letters_only, f"api_key = {letters_only}"),
        Canary("zero_width_inside_token", github, f"x = '{github[:6]}​{github[6:]}'"),
    ]


PEM_BODY = [
    "Zq7Lm2Xv9Tb4Rn8Kc3Hd5Wf1Gy6Js0Pa",
    "Mn4Bv8Cx2Zl6Kj0Hg3Fd7Sa1Qw5Er9Ty",
    "Uo2Ip6Lk0Mj4Nh8Bg3Vf7Cd1Xs5Za9Qw",
    "Er4Ty8Ui2Op6As0Df3Gh7Jk1Lz5Xc9Vb",
    "Nm3Qw7Er1Ty5Ui9Op2As6Df0Gh4Jk8Lz",
    "Xc2Vb6Nm0Qw4Er8Ty3Ui7Op1As5Df9Gh",
    "Ab3Cd9Ef",  # short lines: too short for the entropy fallback, only the block rule catches them
    "Gh5Ij1==",
]


def pem_block() -> list[str]:
    """A private key block as separate source lines (header, body, footer)."""
    label = "RSA " + "PRIVATE " + "KEY"
    return [f"-----BEGIN {label}-----", *PEM_BODY, f"-----END {label}-----"]
