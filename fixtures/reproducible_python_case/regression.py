from app import authorize, SECRET

assert authorize(SECRET) is True
assert authorize(SECRET + "x") is False
assert authorize("safe-ATTACKER-CONTROLLED") is False
print("PASS")
