"""
PII Guard v4 — Indian PII + Resume Anonymizer (server-ready build)
SWYNEX Internship · Task 3 (Intelligent Feature) -> Task 4 (Browser Extension backend)

Task 4 changes over v3.2 — detection logic deliberately UNCHANGED
(see CHANGELOG at the bottom of this file for the exact list):

  1. Long inputs (> 5000 chars) are auto-chunked at paragraph boundaries and
     redacted piece-by-piece instead of being rejected outright.
  2. The report now carries `redaction_count` (how many PII items were masked),
     which powers the extension popup's stats counter.
  3. Falls back to the smaller `en_core_web_sm` spaCy model when the
     recommended `en_core_web_lg` is not installed (weaker NER, same regexes).
  4. Clearer startup error naming the exact fix command.
"""
import logging
import re

logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)

from presidio_analyzer import (
    AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult,
)
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_anonymizer.operators import Operator

try:
    from presidio_anonymizer.operators import OperatorType
    _ANON_TYPE = OperatorType.Anonymize
except ImportError:
    _ANON_TYPE = "Anonymize"


INDIAN_PHONE_REGEX = r"(?<!\d)(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"
AADHAAR_REGEX = r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?![\s-]?\d)"
PAN_REGEX = r"(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])"
CARD_REGEX = r"\b(?:\d[ -]?){13,19}\b"
EMAIL_REGEX = r"[\w.+-]+@[\w-]+\.[\w.]+"
URL_REGEX = r"(?:https?://)?(?:www\.)?(?:linkedin\.com/in/|github\.com/)[\w\-]+/?"
PIN_REGEX = r"(?<!\d)[1-9]\d{5}(?!\d)"
DOB_REGEX = r"(?i)(?:DOB|Date\s+of\s+Birth|D\.O\.B\.?)\s*[:\-]?\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}"


class MaskKeepLast(Operator):
    def operate(self, text, params=None):
        keep = 4
        if params and "keep" in params:
            keep = int(params["keep"])
        if len(text) <= keep:
            return "*" * len(text)
        return "*" * (len(text) - keep) + text[-keep:]

    def operator_name(self):
        return "mask_keep_last"

    def operator_type(self):
        return _ANON_TYPE

    def validate(self, params=None):
        pass


def _build_analyzer():
    """Create the Presidio analyzer.

    Prefers the default `en_core_web_lg` model (best NER accuracy).
    If it is not installed, falls back to `en_core_web_sm` so the server
    still runs on machines with limited disk/bandwidth.
    """
    try:
        return AnalyzerEngine()  # default NLP engine: en_core_web_lg
    except Exception as lg_error:
        print(f"[WARN] Default NLP model (en_core_web_lg) unavailable: {lg_error}")
        print("       Falling back to en_core_web_sm (smaller, slightly weaker NER)...")
        try:
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            })
            return AnalyzerEngine(nlp_engine=provider.create_engine())
        except Exception:
            raise RuntimeError(
                "Could not load any spaCy English model.\n"
                "Fix:  python -m spacy download en_core_web_lg\n"
                "  or: python -m spacy download en_core_web_sm"
            )


print("Loading AI models...\n")
analyzer = _build_analyzer()
anonymizer = AnonymizerEngine()
try:
    anonymizer.add_anonymizer(MaskKeepLast)
except AttributeError as exc:
    raise RuntimeError(
        "This build requires presidio-anonymizer >= 0.0.40 for custom operators. "
        "Run: pip install -U presidio-anonymizer presidio-analyzer"
    ) from exc

try:
    analyzer.registry.remove_recognizer("UrlRecognizer")
except Exception:
    pass

def _add(entity, pattern):
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity=entity, patterns=[pattern])
    )

_add("PHONE_NUMBER", Pattern(name="indian_phone", regex=INDIAN_PHONE_REGEX, score=0.85))
_add("AADHAAR", Pattern(name="aadhaar", regex=AADHAAR_REGEX, score=0.8))
_add("PAN", Pattern(name="pan", regex=PAN_REGEX, score=0.85))
_add("URL", Pattern(name="url", regex=URL_REGEX, score=0.9))
_add("IN_PIN", Pattern(name="in_pin", regex=PIN_REGEX, score=0.6))
_add("DATE_TIME", Pattern(name="dob", regex=DOB_REGEX, score=0.9))

DENY_NAMES = ["Ananda", "Rahul", "Sharma", "Priya", "Arjun", "Sneha"]
INDIAN_STATES = [
    "Maharashtra", "Karnataka", "Tamil Nadu", "Delhi", "Uttar Pradesh", 
    "Gujarat", "West Bengal", "Rajasthan", "Kerala", "Telangana", 
    "Andhra Pradesh", "Madhya Pradesh", "Punjab", "Haryana", "Bihar", 
    "Odisha", "Assam", "Uttarakhand", "Himachal Pradesh", "Goa", 
    "Jharkhand", "Chhattisgarh", "Mumbai", "Bengaluru", "Bangalore", 
    "Chennai", "Kolkata", "Hyderabad", "Pune", "Ahmedabad", "Jaipur"
]

analyzer.registry.add_recognizer(
    PatternRecognizer(supported_entity="PERSON", deny_list=DENY_NAMES)
)
analyzer.registry.add_recognizer(
    PatternRecognizer(supported_entity="LOCATION", deny_list=INDIAN_STATES)
)

ENTITY_RISK_WEIGHTS = {
    "CREDIT_CARD": 1.0, "AADHAAR": 1.0, "PAN": 1.0,
    "PHONE_NUMBER": 0.8, "EMAIL_ADDRESS": 0.7, "URL": 0.6,
    "PERSON": 0.5, "IN_PIN": 0.5, "LOCATION": 0.4,
    "ORGANIZATION": 0.4, "DATE_TIME": 0.3,
}
DEFAULT_WEIGHT = 0.5
REVIEW_FLOOR = 0.25
REDACT_THRESHOLD = 0.4

ALLOW_LIST = ["SWYNEX", "Technologies", "Presidio", "Python", "GitHub", "Google Colab"]

DEFAULT_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON",
                    "CREDIT_CARD", "AADHAAR", "PAN"]
RESUME_ENTITIES = DEFAULT_ENTITIES + ["URL", "LOCATION", "ORGANIZATION",
                                      "DATE_TIME", "IN_PIN"]

OPERATORS = {
    "CREDIT_CARD": OperatorConfig("mask_keep_last", {"keep": 4}),
    "PHONE_NUMBER": OperatorConfig("mask_keep_last", {"keep": 4}),
    "AADHAAR": OperatorConfig("replace", {"new_value": "<AADHAAR>"}),
    "PAN": OperatorConfig("replace", {"new_value": "<PAN>"}),
    "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
    "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
    "URL": OperatorConfig("replace", {"new_value": "<URL>"}),
    "LOCATION": OperatorConfig("replace", {"new_value": "<LOCATION>"}),
    "ORGANIZATION": OperatorConfig("replace", {"new_value": "<ORG>"}),
    "DATE_TIME": OperatorConfig("replace", {"new_value": "<DATE>"}),
    "IN_PIN": OperatorConfig("replace", {"new_value": "<PIN>"}),
    "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
}

FALLBACK_RULES = [
    (re.compile(EMAIL_REGEX), "<EMAIL>"),
    (re.compile(CARD_REGEX), "<CARD>"),
    (re.compile(AADHAAR_REGEX), "<AADHAAR>"),
    (re.compile(PAN_REGEX), "<PAN>"),
    (re.compile(INDIAN_PHONE_REGEX), "<PHONE>"),
]
RESUME_FALLBACK_RULES = [
    (re.compile(URL_REGEX), "<URL>"),
    (re.compile(DOB_REGEX), "<DATE>"),
    (re.compile(PIN_REGEX), "<PIN>"),
]

def regex_fallback(text, resume_mode=False, return_count=False):
    """Pure-regex safety net used if the analyzer/anonymizer ever fails.

    With return_count=True, also returns how many substitutions were made
    (used for the report's `redaction_count` in degraded mode).
    """
    safe, count = text, 0
    for pattern, replacement in FALLBACK_RULES:
        safe, n = pattern.subn(replacement, safe)
        count += n
    if resume_mode:
        for pattern, replacement in RESUME_FALLBACK_RULES:
            safe, n = pattern.subn(replacement, safe)
            count += n
    return (safe, count) if return_count else safe

# ---------------------------------------------------------------------------
# Task 4: chunking support
# ---------------------------------------------------------------------------

MAX_CHARS = 5000  # per-chunk limit fed to the analyzer (was a hard input cap in v3)

def _split_text(text, limit=MAX_CHARS):
    """Split long text into [(piece, separator), ...] pairs.

    Cut points are chosen at paragraph boundaries ('\n\n') whenever possible,
    falling back to a single newline, then a space, then a hard cut. The
    separator that was cut at is preserved so the redacted pieces can be
    re-joined into the original layout.
    """
    if len(text) <= limit:
        return [(text, "")]
    pieces, rest = [], text
    while len(rest) > limit:
        window = rest[:limit]
        cut, sep = limit, ""
        for candidate in ("\n\n", "\n", " "):
            idx = window.rfind(candidate)
            if idx >= int(limit * 0.3):  # avoid tiny trailing fragments
                cut, sep = idx, candidate
                break
        pieces.append((rest[:cut], sep))
        rest = rest[cut + len(sep):]
    pieces.append((rest, ""))
    return pieces

def _trim_person_spans(text, results):
    cleaned = []
    for r in results:
        if r.entity_type == "PERSON":
            snippet = text[r.start:r.end]
            if "\n" in snippet:
                first_line = snippet.split("\n", 1)[0]
                if first_line.strip():
                    cleaned.append(RecognizerResult(
                        entity_type=r.entity_type,
                        start=r.start,
                        end=r.start + len(first_line),
                        score=r.score,
                    ))
                continue
        cleaned.append(r)
    return cleaned

def compute_risk(results):
    if not results:
        return 0.0, "LOW"
    scores = [r.score * ENTITY_RISK_WEIGHTS.get(r.entity_type, DEFAULT_WEIGHT)
              for r in results]
    blended = 0.7 * max(scores) + 0.3 * min(sum(scores), 1.0)
    blended = round(min(blended, 1.0), 2)
    if blended >= 0.7:
        level = "HIGH"
    elif blended >= 0.4:
        level = "MEDIUM"
    else:
        level = "LOW"
    return blended, level

def _new_report(text, resume_mode):
    return {
        "input": text, "output": None, "entities": [], "redaction_count": 0,
        "risk_score": 0.0, "risk_level": "LOW",
        "review": [], "error": None, "resume_mode": resume_mode,
    }

def _protect_single(text, resume_mode, on_failure, verbose):
    """Original v3 pipeline for a single chunk (<= MAX_CHARS)."""
    report = _new_report(text, resume_mode)

    entities = RESUME_ENTITIES if resume_mode else DEFAULT_ENTITIES

    try:
        raw = analyzer.analyze(
            text=text, language="en", entities=entities,
            score_threshold=REVIEW_FLOOR, allow_list=ALLOW_LIST,
        )
    except Exception as exc:
        if on_failure == "block":
            report["error"] = f"Analyzer failed ({exc}); refusing to process (fail-closed)."
            report["risk_level"] = "UNKNOWN"
            if verbose: print(f"[BLOCKED] {report['error']}\n")
            return report
        report["error"] = f"Analyzer failed ({exc}); regex fallback used."
        report["output"], report["redaction_count"] = regex_fallback(
            text, resume_mode, return_count=True)
        report["risk_level"] = "UNKNOWN"
        if verbose:
            print(f"[FALLBACK] {report['error']}")
            print(f"Safe output: {report['output']}\n")
        return report

    raw = _trim_person_spans(text, raw)

    kept, review = [], []
    for r in raw:
        snippet = text[r.start:r.end]
        if r.score >= REDACT_THRESHOLD:
            kept.append(r)
        else:
            review.append(f"{r.entity_type} ('{snippet}', {r.score:.2f})")

    report["entities"] = sorted({r.entity_type for r in kept})
    report["review"] = review
    report["risk_score"], report["risk_level"] = compute_risk(kept)

    try:
        anonymized = anonymizer.anonymize(
            text=text, analyzer_results=kept, operators=OPERATORS,
        )
        report["output"] = anonymized.text
        report["redaction_count"] = len(anonymized.items)
    except Exception as exc:
        if on_failure == "block":
            report["error"] = f"Anonymizer failed ({exc}); refusing to process (fail-closed)."
            report["output"] = None
            if verbose: print(f"[BLOCKED] {report['error']}\n")
            return report
        report["error"] = f"Anonymizer failed ({exc}); regex fallback used."
        report["output"], report["redaction_count"] = regex_fallback(
            text, resume_mode, return_count=True)

    if verbose:
        print("--- Original Input ---")
        print(text)
        print("--- Safe Output (Redacted) ---")
        print(report["output"])
        print(f"Detected: {report['entities'] or 'none'}")
        print(f"Risk: {report['risk_level']} ({report['risk_score']})")
        if report["review"]:
            print(f"Needs human review: {report['review']}")
        if report["error"]:
            print(f"[WARN] {report['error']}")
        print("-" * 60 + "\n")

    return report

def _protect_chunked(pairs, resume_mode, on_failure):
    """Task 4: redact each chunk independently, then merge the reports."""
    merged = _new_report("".join(p + s for p, s in pairs), resume_mode)
    merged["chunked"], merged["chunks"] = True, len(pairs)

    outputs, entities, review = [], set(), []
    worst_error, max_score = None, 0.0

    for piece, sep in pairs:
        r = _protect_single(piece, resume_mode, on_failure, verbose=False)
        if r["output"] is None:
            # A chunk hard-failed (fail-closed mode) — refuse everything.
            merged["output"] = None
            merged["error"] = r["error"]
            merged["risk_level"] = r["risk_level"]
            return merged
        outputs.append(r["output"] + sep)
        entities.update(r["entities"])
        review.extend(r["review"])
        merged["redaction_count"] += r.get("redaction_count", 0)
        max_score = max(max_score, r["risk_score"])
        if r["error"]:
            worst_error = r["error"]

    merged["output"] = "".join(outputs)
    merged["entities"] = sorted(entities)
    merged["review"] = review
    merged["risk_score"] = max_score
    merged["risk_level"] = ("HIGH" if max_score >= 0.7
                            else "MEDIUM" if max_score >= 0.4
                            else "LOW")
    merged["error"] = worst_error
    return merged

def protect_pii(text, verbose=True, resume_mode=False, on_failure="degraded"):
    """Scan `text` for PII and return a report dict.

    Task 4: inputs longer than MAX_CHARS are automatically split at paragraph
    boundaries and redacted chunk-by-chunk (v3 rejected them with an error).
    """
    if not isinstance(text, str):
        report = _new_report(text, resume_mode)
        report["error"] = "Input must be a string."
        if verbose: print(f"[ERROR] {report['error']}\n")
        return report
    if not text.strip():
        report = _new_report(text, resume_mode)
        report["error"] = "Input is empty — nothing to scan."
        if verbose: print(f"[ERROR] {report['error']}\n")
        return report

    pairs = _split_text(text)
    if len(pairs) > 1:
        return _protect_chunked(pairs, resume_mode, on_failure)
    return _protect_single(text, resume_mode, on_failure, verbose)

def redact_resume(text):
    return protect_pii(text, verbose=False, resume_mode=True)

SAMPLE_TEXTS = [
    "Hi, my name is Ananda and my email is ananda@example.com.",
    "Call me at +91 99953 88012 or 9995388012.",
    "Aadhaar: 2345 6789 0123 | PAN: ABCDE1234F",
    "Please charge my card: 4111 1111 1111 1111.",
    "I work at SWYNEX Technologies and I love Python.",
]

RESUME_SAMPLE = """Rahul Sharma
Email: rahul.sharma@example.com | Phone: +91 98765 43210
LinkedIn: linkedin.com/in/rahulsharma | GitHub: github.com/rahulsharma
Location: Bengaluru, Karnataka - 560001
DOB: 15/08/1998 | Aadhaar: 2345 6789 0123 | PAN: ABCDE1234F
Education: B.Tech, IIT Madras (2016-2020)
Experience: Software Engineer at Infosys (2020-2023)"""

def run_samples():
    print("=" * 60)
    print("STANDARD MODE SAMPLES")
    print("=" * 60)
    for text in SAMPLE_TEXTS:
        protect_pii(text)
    print("=" * 60)
    print("RESUME MODE SAMPLE")
    print("=" * 60)
    protect_pii(RESUME_SAMPLE, resume_mode=True)

def interactive_demo():
    print("=== PII Guard v3 ===")
    print("1. Scan your own text")
    print("2. Run built-in samples")
    print("3. Toggle resume mode")
    print("4. Exit")
    resume_mode = False
    while True:
        try:
            choice = input("Choose 1/2/3/4: ").strip()
        except EOFError:
            break
        if choice == "1":
            try:
                user_text = input("Paste your text: ")
            except EOFError:
                break
            protect_pii(user_text, resume_mode=resume_mode)
        elif choice == "2":
            run_samples()
        elif choice == "3":
            resume_mode = not resume_mode
            print(f"Resume mode is now {'ON' if resume_mode else 'OFF'}.")
        elif choice == "4":
            print("Bye!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    run_samples()

# ---------------------------------------------------------------------------
# CHANGELOG  v3.2 -> v4  (Task 4, every change logged)
# ---------------------------------------------------------------------------
# ADDED   : MAX_CHARS + _split_text() + _protect_chunked() — inputs longer
#           than 5000 chars are now chunked at paragraph boundaries and
#           redacted piece-by-piece. v3.2 rejected them with an error.
#           Behaviour for inputs <= 5000 chars is byte-for-byte identical.
# ADDED   : report["redaction_count"] — number of PII items masked
#           (len(anonymizer items), or regex sub count in fallback mode).
# ADDED   : report["chunked"] / report["chunks"] — set when chunking kicks in.
# ADDED   : regex_fallback(..., return_count=True) variant used by the server.
# ADDED   : _build_analyzer() — automatic en_core_web_lg -> en_core_web_sm
#           model fallback with a clear warning, and a startup error that
#           names the exact fix command.
# CHANGED : protect_pii() split into protect_pii() (validation + dispatch)
#           and _protect_single() (original pipeline body). Public API,
#           parameters and return keys are unchanged (plus new keys above).
# UNCHANGED: all regexes, ENTITY_RISK_WEIGHTS, REVIEW_FLOOR, REDACT_THRESHOLD,
#           ALLOW_LIST, DENY_NAMES, INDIAN_STATES, OPERATORS, MaskKeepLast,
#           SAMPLE_TEXTS, RESUME_SAMPLE, run_samples(), interactive_demo().
# ---------------------------------------------------------------------------
