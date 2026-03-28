def finalize_result(risk, reasons):
    """
    Convert risk score into final status.
    Better balanced thresholds:
    0-29   = Safe
    30-64  = Suspicious
    65-100 = Fraud
    """
    if risk < 30:
        status = "Safe"
    elif risk < 65:
        status = "Suspicious"
    else:
        status = "Fraud"

    # Clamp risk between 0 and 100
    risk = max(0, min(100, int(risk)))

    return {
        "status": status,
        "risk": risk,
        "reasons": reasons
    }