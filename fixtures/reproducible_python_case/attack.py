from app import authorize

payload = "safe-ATTACKER-CONTROLLED"
if authorize(payload):
    print("VULNERABLE")
    print("source_location=app.py:authorize")
    print("root_cause=prefix comparison allows attacker-controlled suffixes to bypass exact-token semantics")
else:
    print("SAFE")
raise SystemExit(0)
