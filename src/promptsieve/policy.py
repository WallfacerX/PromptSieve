from .models import Finding


def decide(mode: str, findings: list[Finding]) -> str:
    flagged = any(f.severity in {"medium", "high"} for f in findings)
    if mode == "monitor":
        return "monitor" if flagged else "allow"
    return "block" if flagged else "allow"
