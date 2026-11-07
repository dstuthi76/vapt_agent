"""Contextual risk prioritization.

    risk = base x exposure x exploitability x asset_criticality x confidence_weight   (capped at 10)

  base            : tool-supplied CVSS base score; if a tool gave none, the midpoint of the tool's
                    qualitative severity (and the report says so). CVSS is never invented.
  exposure        : from the scope file (external 1.2 / dmz 1.1 / internal 1.0)
  exploitability  : 1.2 if an approved check confirmed it; 1.15 if a tool reported a public exploit;
                    0.9 if the finding rests only on version/banner inference; else 1.0
  asset criticality: from the scope file (high 1.15 / medium 1.0 / low 0.85)
  confidence_weight: 0.5 + 0.5 x calibrated confidence

The risk score is the agent's *priority* score and is reported separately from CVSS."""
from .knowledge import SEVERITY_BASE

EXPOSURE = {"external": 1.2, "dmz": 1.1, "internal": 1.0}
CRITICALITY = {"high": 1.15, "medium": 1.0, "low": 0.85}


def prioritize(findings, scope):
    for f in findings:
        meta = scope.meta_for(f.affected[0]["asset"]) if f.affected else {}
        if f.cvss_score is not None:
            base, base_src = f.cvss_score, f"CVSS {f.cvss_score} ({f.cvss_source})"
        else:
            base, base_src = SEVERITY_BASE[f.severity], f"severity-derived ({f.severity}); no CVSS supplied by tool"
        exposure = EXPOSURE.get(meta.get("exposure", "internal"), 1.0)
        if f.status == "confirmed":
            expl, expl_src = 1.2, "confirmed by approved validation"
        elif f.exploit_available:
            expl, expl_src = 1.15, "tool reports public exploit available"
        elif f.version_inferred:
            expl, expl_src = 0.9, "version/banner inference only"
        else:
            expl, expl_src = 1.0, "no exploitability data"
        crit = CRITICALITY.get(meta.get("criticality", "medium"), 1.0)
        cw = 0.5 + 0.5 * f.confidence
        score = round(min(10.0, base * exposure * expl * crit * cw), 1)
        if f.status in ("false_positive",):
            score = 0.0
        f.risk_score = score
        f.risk_breakdown = {
            "base": base, "base_source": base_src, "exposure": exposure, "exposure_source": meta.get("exposure", "internal"),
            "exploitability": expl, "exploitability_source": expl_src, "asset_criticality": crit,
            "criticality_source": meta.get("criticality", "medium"), "confidence_weight": round(cw, 2),
            "formula": f"{base} x {exposure} x {expl} x {crit} x {round(cw, 2)} = {score}",
        }
        f.priority = "P1" if score >= 8.5 else "P2" if score >= 6.5 else "P3" if score >= 4.0 else "P4" if score > 0 else "Info"
        if f.status == "false_positive":
            f.priority = "FP"
    findings.sort(key=lambda f: (-f.risk_score, f.title))
    return findings
