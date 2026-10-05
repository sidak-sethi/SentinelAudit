SECRET = "safe-token"


def authorize(token: str) -> bool:
    # Intentional fixture flaw: prefix matching permits an attacker-controlled suffix.
    return token == SECRET
