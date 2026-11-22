from .models import ExposureValidation


def review_exposure(investigation, references):
    """Record what evidence exists for human review, without running behavior probes."""
    cited = set(investigation.evidence_ids) if investigation else set()
    tests = [ref.id for ref in references if ref.id in cited and
             (ref.path.startswith(("test/", "tests/")) or ".spec." in ref.path)]
    checks = ["No approved behavior test was executed."]
    if tests:
        checks.append("Investigation cited existing test references.")
    return ExposureValidation(result="unable to validate", evidence_ids=tests, checks=checks)
