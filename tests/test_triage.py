from smishguard.analyzers import triage_sms

def test_usps_smish_high():
    msg = "UNITED STATES POSTAL SERVICE Urgent Notice Please Check Attachment. USPS.COM/REDELIVERY CLICK HERE"
    res = triage_sms(msg, from_number="+1 (705) 854-1876", attachment="USPS-Notice-USD497.pdf")
    assert res.risk == "HIGH"
    assert res.score >= 70
    assert "usps.com" in [d.lower() for d in res.domains]

def test_benign_low():
    msg = "Hey are we still meeting at 6?"
    res = triage_sms(msg, from_number="+1 (202) 555-0199")
    assert res.risk in ("LOW", "MEDIUM")
