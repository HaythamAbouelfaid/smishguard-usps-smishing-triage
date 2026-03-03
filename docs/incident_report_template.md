# Incident Report (1-Page) — SMiShing (USPS Redelivery Lure)

**Incident ID:** IR-YYYYMMDD-###
**Date/Time Reported:**  
**Reported By:**  
**Category:** SMiShing / Phishing  
**Severity:** (Low/Med/High)  

## Executive Summary
A recipient received an SMS claiming to be the United States Postal Service (USPS) stating a package could not be delivered due to incomplete/damaged label information. The message urged the user to click a redelivery link and/or open a PDF attachment. This matches common **credential/payment harvesting** and **malware delivery** patterns.

## Observed Indicators
- **Sender phone:**  
- **Attachment filename:**  
- **URLs/domains:**  
- **Keywords/lure text:** (e.g., urgent notice, unable to deliver, click here)

## Analysis (What makes it malicious)
- Brand impersonation + urgency + call-to-action
- Unsolicited attachment and/or link
- Delivery problem pretext is a common lure for identity/payment data theft

## Recommended Actions
**For the user:**
- Do not click/open anything; delete message
- If clicked: reset passwords for any entered accounts; enable MFA; run AV scan; monitor bank/CC activity

**For IT/Security:**
- Block domains/URLs (if identifiable)
- Add sender number to blocklist (as appropriate)
- Create detection rule for keywords/attachment patterns
- Communicate advisory to users

## Evidence
- Screenshot(s) attached
- Attachment hash (if obtained): SHA256:  
