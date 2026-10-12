import base64
import re
import unicodedata

from .models import Finding, Segment

RULES = (
    (
        "instruction_override",
        "instruction_override",
        r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,65}"
        r"\b(?:instructions|rules|restrictions|safeguards|safety policy)\b",
        "Attempts to override governing instructions",
    ),
    (
        "role_spoofing",
        "role_spoofing",
        r"(?:<\|(?:im_start|system|developer)\|>|\[/?INST\]|"
        r"(?:^|\n)\s*(?:system|developer)\s*:|"
        r"\byou are now\b.{0,40}\b(?:unrestricted|DAN|jailbroken)\b)",
        "Attempts to impersonate a privileged instruction source",
    ),
    (
        "prompt_extraction",
        "system_prompt_extraction",
        r"\b(?:reveal|print|repeat|show|disclose|return|output)\b.{0,65}"
        r"\b(?:system prompt|developer message|hidden instructions|initial instructions)\b",
        "Requests disclosure of privileged instructions",
    ),
)
PATTERNS = [(i, c, re.compile(p, re.I | re.S), r) for i, c, p, r in RULES]
ANALYTICAL = re.compile(r"\b(?:explain|analy[sz]e|discuss|example|quotation|quoted|detect)\b", re.I)


def normalize(text):
    return "".join(
        c for c in unicodedata.normalize("NFKC", text) if unicodedata.category(c) != "Cf"
    )


class BaselineDetector:
    def inspect(self, segment: Segment) -> list[Finding]:
        text = normalize(segment.text)
        findings = []
        for detector_id, category, pattern, reason in PATTERNS:
            severity = None
            for match in pattern.finditer(text):
                # Only downgrade a locally quoted analytical example, never the whole request.
                start = (
                    max(
                        text.rfind("\n", max(0, match.start() - 256), match.start()),
                        text.rfind(".", max(0, match.start() - 256), match.start()),
                        match.start() - 257,
                    )
                    + 1
                )
                prefix = text[start : match.start()]
                suffix = text[match.end() : match.end() + 100]
                quoted = any(prefix.count(q) % 2 and q in suffix for q in ('"', "`", "'"))
                negated = re.search(r"(?:do not|never|don't)\s+$", prefix, re.I)
                low = (quoted and ANALYTICAL.search(prefix)) or negated
                severity = "low" if low else "high"
                if not low:
                    break
            if severity:
                findings.append(
                    Finding(
                        detector_id=detector_id,
                        category=category,
                        severity=severity,
                        field=segment.field,
                        reason=reason,
                    )
                )
        variants = []
        for token in re.findall(r"(?<!\w)[A-Za-z0-9+/=]{24,2048}(?!\w)", text)[:16]:
            try:
                variants.append(base64.b64decode(token, validate=True).decode("utf-8"))
            except (ValueError, UnicodeError):
                pass
        for token in re.findall(r"(?<!\w)(?:[0-9a-fA-F]{2}){12,1024}(?!\w)", text)[:16]:
            try:
                variants.append(bytes.fromhex(token).decode("utf-8"))
            except (ValueError, UnicodeError):
                pass
        encoded_attack = any(p.search(normalize(v)) for v in variants for _, _, p, _ in PATTERNS)
        altered_attack = text != segment.text and any(f.severity == "high" for f in findings)
        if encoded_attack or altered_attack:
            findings.append(
                Finding(
                    detector_id="obfuscation",
                    category="obfuscation",
                    severity="high",
                    field=segment.field,
                    reason="Obfuscated text contains an instruction attack pattern",
                )
            )
        return findings
