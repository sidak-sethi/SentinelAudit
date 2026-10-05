from pathlib import Path

p = Path("app.py")
text = p.read_text(encoding="utf-8")
text = text.replace("return token.startswith(SECRET[:4])", "return token == SECRET")
p.write_text(text, encoding="utf-8")
print("PATCH_APPLIED")
