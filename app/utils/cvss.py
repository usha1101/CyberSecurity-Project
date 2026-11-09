import math
from typing import Dict, Any, Tuple
from app.models.response import CVSSMetrics


def cvss_round_up(val: float) -> float:
    """Official CVSS v3.1 round_up function defined by FIRST.org."""
    input_scaled = round(val * 100000)
    if input_scaled % 10000 == 0:
        return input_scaled / 100000.0
    else:
        return (math.floor(input_scaled / 10000) + 1) / 10.0


# CVSS v3.1 Metric Weight Tables
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
IMPACT_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}


def calculate_cvss_v31(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    s: str = "U",
    c: str = "H",
    i: str = "H",
    a: str = "H",
) -> CVSSMetrics:
    """Calculates official CVSS v3.1 base score, exploitability, impact, and vector."""
    # Normalize inputs
    av = av.upper() if av.upper() in AV_WEIGHTS else "N"
    ac = ac.upper() if ac.upper() in AC_WEIGHTS else "L"
    s = s.upper() if s.upper() in ["U", "C"] else "U"
    pr = pr.upper() if pr.upper() in PR_WEIGHTS[s] else "N"
    ui = ui.upper() if ui.upper() in UI_WEIGHTS else "N"
    c = c.upper() if c.upper() in IMPACT_WEIGHTS else "H"
    i = i.upper() if i.upper() in IMPACT_WEIGHTS else "H"
    a = a.upper() if a.upper() in IMPACT_WEIGHTS else "H"

    av_val = AV_WEIGHTS[av]
    ac_val = AC_WEIGHTS[ac]
    pr_val = PR_WEIGHTS[s][pr]
    ui_val = UI_WEIGHTS[ui]

    c_val = IMPACT_WEIGHTS[c]
    i_val = IMPACT_WEIGHTS[i]
    a_val = IMPACT_WEIGHTS[a]

    # ISS = 1 - [ (1 - ImpactConf) * (1 - ImpactInteg) * (1 - ImpactAvail) ]
    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

    # Impact sub-score
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

    # Exploitability sub-score
    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    # Base Score calculation
    if impact <= 0:
        base_score = 0.0
    else:
        if s == "U":
            base_score = cvss_round_up(min(impact + exploitability, 10.0))
        else:
            base_score = cvss_round_up(min(1.08 * (impact + exploitability), 10.0))

    # Qualitative Severity Rating
    if base_score == 0.0:
        severity = "NONE"
    elif 0.1 <= base_score <= 3.9:
        severity = "LOW"
    elif 4.0 <= base_score <= 6.9:
        severity = "MEDIUM"
    elif 7.0 <= base_score <= 8.9:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    vector_string = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    return CVSSMetrics(
        vector_string=vector_string,
        base_score=round(base_score, 1),
        severity_rating=severity,
        exploitability_score=round(exploitability, 2),
        impact_score=round(impact, 2),
        metrics={
            "AV": av,
            "AC": ac,
            "PR": pr,
            "UI": ui,
            "S": s,
            "C": c,
            "I": i,
            "A": a,
        },
    )


def parse_cvss_vector(vector_str: str) -> Dict[str, str]:
    """Parses a CVSS 3.1 vector string into metric key-value pairs."""
    result = {}
    parts = vector_str.split("/")
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            if k != "CVSS":
                result[k.strip().upper()] = v.strip().upper()
    return result

