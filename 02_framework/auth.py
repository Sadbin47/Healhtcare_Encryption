"""Application authentication primitives for the deployable API.

Tokens are deliberately small and file/config friendly.  WireGuard controls
network admission; this layer identifies the caller and enforces endpoint roles.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Principal:
    actor_id: str
    role: str


class AuthenticationError(PermissionError):
    """Raised when a bearer token is missing, invalid, or mis-scoped."""


class TokenAuthenticator:
    """Constant-time token lookup with role and actor binding.

    ``tokens`` maps opaque bearer tokens to ``Principal`` objects.  Tokens are
    kept in memory only; callers should load them from a root-readable env file.
    """

    def __init__(self, tokens: Mapping[str, Principal | tuple[str, str]]) -> None:
        self._tokens: dict[str, Principal] = {}
        for token, principal in tokens.items():
            if not isinstance(token, str) or not token:
                raise ValueError("authentication tokens must be non-empty strings")
            if isinstance(principal, Principal):
                value = principal
            else:
                try:
                    value = Principal(actor_id=str(principal[0]), role=str(principal[1]).lower())
                except (IndexError, TypeError) as error:
                    raise ValueError("token principals must be Principal or (actor_id, role)") from error
            if not value.actor_id or not value.role:
                raise ValueError("token principal actor_id and role are required")
            self._tokens[token] = value

    @classmethod
    def from_environment(cls, value: str | None) -> "TokenAuthenticator":
        """Parse ``token=actor:role,...`` configuration without logging secrets."""

        tokens: dict[str, Principal] = {}
        if value:
            for item in value.split(","):
                token, separator, identity = item.partition("=")
                actor, role_separator, role = identity.rpartition(":")
                if not separator or not role_separator or not token or not actor or not role:
                    raise ValueError("tokens must use token=actor:role entries")
                tokens[token] = Principal(actor_id=actor, role=role.lower())
        return cls(tokens)

    def principal_for(self, token: str | None) -> Principal:
        if not isinstance(token, str) or not token:
            raise AuthenticationError("request authentication failed")
        # Avoid exposing whether a token prefix exists through a direct dict
        # comparison.  Hashing also keeps the actual secret out of exceptions.
        digest = hashlib.sha256(token.encode("utf-8"))
        for candidate, principal in self._tokens.items():
            if hmac.compare_digest(digest.digest(), hashlib.sha256(candidate.encode("utf-8")).digest()):
                return principal
        raise AuthenticationError("request authentication failed")

    def authorize(self, token: str | None, *, role: str, actor_id: str | None = None) -> Principal:
        principal = self.principal_for(token)
        if principal.role != role.lower():
            raise AuthenticationError("request role is not permitted")
        if actor_id is not None and principal.role != "admin" and principal.actor_id != actor_id:
            raise AuthenticationError("request actor does not match authenticated identity")
        return principal
