# =============================================================================
#  DecodeLabs Industrial Training Kit | Batch 2026
#  Cyber Security — Project 3: Phishing Awareness Analysis
#  Track   : Junior Analyst // Detection Phase
#  Status  : Submission Ready
# =============================================================================
#
#  MISSION (Slide 5):
#  "The modern cybersecurity perimeter is no longer the network firewall.
#   It is the USER." — Building the Human Firewall.
#
#  ANATOMY OF A SOCIAL ENGINEERING ATTACK (Slide 8):
#  INPUT  (The Bait)      → delivery method & technical disguise
#  PROCESS (The Psychology) → cognitive triggers that bypass logic
#  OUTPUT (The Defense)    → simulation, triage, and reporting
#
#  TRIAGE DECISION TREE (Slide 24):
#  Safe → CLOSE | Suspicious → WARN USER | Malicious → BLOCK & ESCALATE
#
#  ALL 11 RED FLAGS IMPLEMENTED (Slides 15-17):
#  RF-01  Sender-Domain Mismatch      RF-07  Activity Alerts
#  RF-02  Fake Forwarded Chains        RF-08  MFA Fatigue
#  RF-03  Browser-in-the-Browser       RF-09  Security Callback Scams (TOAD)
#  RF-04  Dangerous Attachments        RF-10  QR Code Prompts
#  RF-05  Urgent Bypass Requests       RF-11  Deepfake Live-Meeting Fraud
#  RF-06  Requests for Sensitive Info
# =============================================================================

import re
import textwrap


# =============================================================================
#  SECTION 1 — RED FLAGS DATABASE
#  All 11 red flags extracted directly from slides 15, 16, 17
# =============================================================================

RED_FLAGS = {

    # ── Slide 15 ──────────────────────────────────────────────────────────────

    "RF-01": {
        "name"       : "Sender-Domain Mismatch",
        "slide"      : 15,
        "description": (
            "The display name shows a trusted brand (e.g., 'Microsoft Support') "
            "but the actual routing domain is external and unrelated "
            "(e.g., support@logins-updates.com). Mobile clients are especially "
            "vulnerable as they hide the raw address. Always inspect full headers."
        ),
        "keywords"   : [
            "support@logins", "noreply@", "admin@", "security@",
            "microsoft@gmail", "paypal@yahoo", "amazon@hotmail",
            "apple@outlook", "service@", "alert@", "verify@",
            "account@", "no-reply@"
        ],
        "severity"   : "HIGH",
    },

    "RF-02": {
        "name"       : "Fake Forwarded Chains",
        "slide"      : 15,
        "description": (
            "Subject lines starting with 'FW:' or 'RE:' that contain pasted "
            "headers and odd timestamps of conversations the recipient was never "
            "part of. Attackers use this to build false legitimacy."
        ),
        "keywords"   : ["FW:", "Fwd:", "RE: RE: RE:", "----Original Message----",
                         "forwarded message", "on behalf of"],
        "severity"   : "MEDIUM",
    },

    "RF-03": {
        "name"       : "Browser-in-the-Browser (BitB) / Fake SSO Pop-up",
        "slide"      : 15,
        "description": (
            "Fake Single Sign-On pop-ups embedded in web pages that cannot be "
            "dragged outside the main browser window. Victims enter credentials "
            "into a convincing but entirely fake login overlay."
        ),
        "keywords"   : ["sign in with google", "sign in with microsoft",
                         "sign in with apple", "sso", "single sign-on",
                         "login with your account", "verify your identity"],
        "severity"   : "HIGH",
    },

    "RF-04": {
        "name"       : "Dangerous Attachments",
        "slide"      : 15,
        "description": (
            "Uncommon file extensions (.iso, .js, .scr, .hta, .vbs, .exe, .bat) "
            "or HTML smuggling links disguised as standard documents (invoices, "
            "security updates). The payload executes on open."
        ),
        "keywords"   : [".iso", ".scr", ".hta", ".vbs", ".js attachment",
                         ".exe", ".bat", "security_update", "invoice_",
                         "document.html", "statement_"],
        "severity"   : "CRITICAL",
    },

    # ── Slide 16 ──────────────────────────────────────────────────────────────

    "RF-05": {
        "name"       : "Urgent Bypass Requests",
        "slide"      : 16,
        "description": (
            "Demands for secrecy ('Do not discuss with anyone') or explicit "
            "instructions to bypass normal procedures ('bypass standard procedure', "
            "'strictly confidential'). A legitimate authority never requires "
            "you to skip verification."
        ),
        "keywords"   : [
            "do not discuss", "strictly confidential", "bypass",
            "keep this confidential", "do not tell", "don't tell anyone",
            "between us", "urgent wire", "wire transfer", "immediate action",
            "act now", "respond immediately", "before close of business",
            "before end of day", "within 24 hours", "within 30 minutes",
            "account will be locked", "account locked", "suspended"
        ],
        "severity"   : "CRITICAL",
    },

    "RF-06": {
        "name"       : "Request for Sensitive Information",
        "slide"      : 16,
        "description": (
            "Unexpected prompts for MFA codes, passwords, payment details, "
            "or credential changes over email. Legitimate services NEVER ask "
            "for your password or OTP via email."
        ),
        "keywords"   : [
            "enter your password", "confirm your password", "enter your otp",
            "enter your mfa code", "provide your credentials",
            "update your billing", "update payment", "credit card",
            "bank account", "routing number", "social security",
            "date of birth", "mother's maiden", "security question"
        ],
        "severity"   : "CRITICAL",
    },

    "RF-07": {
        "name"       : "Alarmist Activity Alerts",
        "slide"      : 16,
        "description": (
            "Unusual sign-in warnings that point directly to a login page instead "
            "of advising the user to navigate manually. The goal is to redirect "
            "the user to a credential-harvesting lookalike page."
        ),
        "keywords"   : [
            "unusual sign-in", "suspicious activity", "unauthorized access",
            "someone tried to", "sign-in from unknown", "new device detected",
            "click here to secure", "click here to verify",
            "verify your account now", "confirm your identity"
        ],
        "severity"   : "HIGH",
    },

    "RF-08": {
        "name"       : "MFA Fatigue",
        "slide"      : 16,
        "description": (
            "Multiple, unprompted authenticator push notifications designed to "
            "wear the user down until they approve one. Sometimes combined with "
            "a call impersonating IT support urging the user to 'just approve it'."
        ),
        "keywords"   : [
            "approve the mfa", "approve the request", "just click approve",
            "mfa push", "authenticator notification", "authentication request",
            "approve sign-in", "confirm the login"
        ],
        "severity"   : "HIGH",
    },

    # ── Slide 17 ──────────────────────────────────────────────────────────────

    "RF-09": {
        "name"       : "Security Callback Scam (TOAD)",
        "slide"      : 17,
        "description": (
            "Telephone-Oriented Attack Delivery: emails containing NO malicious "
            "links, only a phone number urging the user to call Support to resolve "
            "a fake subscription charge. The malicious payload is delivered "
            "verbally over the phone."
        ),
        "keywords"   : [
            "call 1-800", "call us at", "call immediately",
            "subscription charge", "unauthorized charge", "call to cancel",
            "contact support", "1-800-", "+1-800",
            "payment overdue", "call now to resolve"
        ],
        "severity"   : "HIGH",
    },

    "RF-10": {
        "name"       : "Unsolicited QR Code Prompt",
        "slide"      : 17,
        "description": (
            "Unsolicited QR codes demanding a scan to 'secure your account' or "
            "'recover access'. These bypass desktop URL filters entirely by "
            "routing the victim to spoofed domains on their unmanaged mobile device."
        ),
        "keywords"   : [
            "scan qr", "scan the code", "qr code", "scan to unlock",
            "scan to verify", "scan to recover", "scan to confirm"
        ],
        "severity"   : "HIGH",
    },

    "RF-11": {
        "name"       : "Deepfake / Impersonation Fraud",
        "slide"      : 17,
        "description": (
            "Audio or video impersonation of an executive during an ad-hoc "
            "meeting, demanding mid-call vendor payment changes. Also includes "
            "AI-generated voicemails followed by emails asking to 'confirm as "
            "discussed' to exploit trust in familiar voices."
        ),
        "keywords"   : [
            "as we discussed", "as discussed on the call", "voicemail",
            "confirm asap", "per our conversation", "i just called you",
            "i left you a voicemail", "change vendor", "update vendor payment",
            "change bank details", "new account details"
        ],
        "severity"   : "CRITICAL",
    },
}


# =============================================================================
#  SECTION 2 — DOMAIN SPOOFING DETECTOR
#  Covers slide 12: Typosquatting, Homoglyph Attacks, Combosquatting
#  Covers slide 13: Subdomain Trap — read URLs right to left
# =============================================================================

TRUSTED_BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "github", "decodelabs", "bankofamerica", "chase", "wellsfargo",
    "chatgpt", "openai", "zoom", "slack"
]

SUSPICIOUS_URL_PATTERNS = [
    # Typosquatting (slide 12)
    r"amaz[0o]n\.com",              # amaz0n.com
    r"g[0o]{2}gle\.com",            # g00gle.com
    r"micros[0o]ft\.com",           # micros0ft.com
    r"paypa[l1]\.com",              # paypa1.com
    r"app[l1]e\.com",               # app1e.com

    # Combosquatting (slide 12)
    r"\w+-secure-login\.",          # brand-secure-login.com
    r"\w+-login-update\.",          # brand-login-update.com
    r"\w+-account-verify\.",        # brand-account-verify.com
    r"\w+-support-center\.",        # brand-support-center.com
    r"logins?-updates?\.",          # logins-updates.com
    r"security-alert\.",            # security-alert.com
    r"verify-\w+\.",                # verify-account.com

    # Subdomain Trap (slide 13) — real domain buried at the end
    r"[a-z]+\.[a-z]+\.[a-z]+\.[a-z]+-[a-z]+\.com",

    # Suspicious TLDs / free hosting
    r"\.(tk|ml|ga|cf|gq|xyz|top|click|link|online|site)\b",

    # URL shorteners hiding real destination
    r"(bit\.ly|tinyurl|t\.co|ow\.ly|goo\.gl|rb\.gy)/",

    # IP addresses instead of domain names
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
]

COGNITIVE_TRIGGERS = {
    "URGENCY"   : ["urgent", "immediately", "right now", "act fast", "limited time",
                    "expires soon", "24 hours", "30 minutes", "today only",
                    "account will be suspended", "locked out"],
    "AUTHORITY"  : ["ceo", "cfo", "it department", "hr department", "legal team",
                    "irs", "fbi", "police", "government", "official notice",
                    "management directive", "executive request"],
    "FEAR/GREED" : ["legal action", "lawsuit", "penalty", "fine", "you won",
                    "congratulations", "selected", "reward", "prize", "gift card",
                    "tax refund", "inheritance", "million dollars"],
    "CURIOSITY"  : ["see what", "look at this", "your colleague said",
                    "someone mentioned you", "photo of you", "check this out",
                    "you won't believe"],
}


# =============================================================================
#  SECTION 3 — SAMPLE PHISHING EMAILS (from Simulation Toolkit, Slides 20-22)
#  5 realistic examples covering all major attack types
# =============================================================================

SAMPLE_EMAILS = [

    {
        "id"      : "EMAIL-01",
        "type"    : "Business Email Compromise (BEC) — Whaling",
        "from"    : "CEO - STRICTLY CONFIDENTIAL <ceo.urgent@executive-update.com>",
        "to"      : "finance@company.com",
        "subject" : "IMMEDIATE ACTION REQUIRED: Transfer Authorization",
        "body"    : """
URGENT: Process the attached wire transfer instruction immediately.

This is critical and must remain STRICTLY CONFIDENTIAL.

Do not discuss with anyone. Bypass standard procedure.
Complete this before close of business today.

Amount: $47,500
Beneficiary: [Vendor Name]
Account: [Routing details in attachment]

Thank you.

CEO
        """,
        "attachment": "Transfer_Auth_2026.iso",
    },

    {
        "id"      : "EMAIL-02",
        "type"    : "Mass Phishing — Credential Harvesting (Microsoft Impersonation)",
        "from"    : "Microsoft Support <support@logins-updates.com>",
        "to"      : "user@company.com",
        "subject" : "FW: Urgent: Your Account Security Alert",
        "body"    : """
FW: Urgent: Your Account Security Alert

----Original Message----
From: Microsoft Security <security@microsoft.com>
Sent: Thursday, June 12, 2026

Dear Valued Customer,

We have detected unusual sign-in activity on your Microsoft account
from an unknown device located in Russia.

Your account will be locked in 30 minutes if you do not verify your identity.

Click here to verify your account now:
http://microsoft-account-verify.logins-updates.com/secure-login

Enter your password and MFA code to confirm your identity and secure your account.

Microsoft Support Team
        """,
        "attachment": None,
    },

    {
        "id"      : "EMAIL-03",
        "type"    : "Callback Phishing (TOAD) — Fake Subscription",
        "from"    : "Microsoft Billing <billing@ms-subscription-renewal.xyz>",
        "to"      : "user@company.com",
        "subject" : "PAYMENT OVERDUE: Your Microsoft Subscription",
        "body"    : """
Microsoft Subscription Renewal Notice

Your Microsoft 365 subscription payment has FAILED.

Order Number: 5001290533333
Subscription Charge: $190.60
Status: PAYMENT OVERDUE

To avoid immediate service interruption and account suspension,
call our billing support team immediately:

Call 1-800-XXX-XXXX to cancel IMMEDIATELY.

Do NOT ignore this notice. Failure to call within 24 hours will result
in legal action and a $350 late payment penalty.

Microsoft Billing Department
        """,
        "attachment": None,
    },

    {
        "id"      : "EMAIL-04",
        "type"    : "Spear Phishing — HR Internal Impersonation",
        "from"    : "Human Resources <hr-policy@company-benefits-update.com>",
        "to"      : "all-staff@company.com",
        "subject" : "Action Required: 2026 Healthcare Benefits Questionnaire",
        "body"    : """
Dear Team Member,

As part of our 2026 Healthcare Benefits enrollment, all employees must
complete the mandatory benefits questionnaire by Friday, June 14, 2026.

Failure to complete this form will result in automatic disenrollment
from your current healthcare plan.

Please complete your questionnaire here:
https://company-hr-benefits-2026.yourcompany-secure-login.com/questionnaire

You will need to confirm:
- Date of birth
- Social Security Number (last 4 digits)
- Current banking information for direct deposit updates
- Mother's maiden name (security verification)

This is strictly confidential. Do not discuss this email with IT.

Human Resources Department
        """,
        "attachment": "Benefits_Form_2026.hta",
    },

    {
        "id"      : "EMAIL-05",
        "type"    : "Deepfake Follow-up / Vishing Combo",
        "from"    : "Director Finance <d.wilson@company-finance-dept.tk>",
        "to"      : "accountspayable@company.com",
        "subject" : "Re: My Voice Message — Vendor Payment Change",
        "body"    : """
Hi,

I just left you a voicemail regarding the urgent request we discussed
on the call earlier. Please confirm ASAP.

Our vendor Quanta Systems has updated their bank account details.
Please change vendor payment to the new account details effective immediately:

New Account: [see attached PDF]

As we discussed, this is time-sensitive. Please update before end of day
and confirm back to me. Do not route through standard procurement —
I've already approved this at the executive level.

Per our conversation, keep this between us until the transfer clears.

Thanks,
D. Wilson
Director of Finance
        """,
        "attachment": "New_Vendor_Details.scr",
    },
]


# =============================================================================
#  SECTION 4 — PHISHING ANALYZER ENGINE
# =============================================================================

def analyze_email(email: dict) -> dict:
    """
    Analyzes a single email against all 11 red flags, domain spoofing patterns,
    and cognitive trigger psychology (slides 12-17).

    Returns a full triage report following the decision tree (slide 24):
    Safe → CLOSE | Suspicious → WARN USER | Malicious → BLOCK & ESCALATE
    """

    full_text    = (
        (email.get("from",       "") + " " +
         email.get("subject",    "") + " " +
         email.get("body",       "") + " " +
         (email.get("attachment") or ""))
    ).lower()

    findings            = []
    triggered_flags     = []
    triggered_urls      = []
    triggered_triggers  = {}
    severity_score      = 0

    SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    # ── Check all 11 red flags ─────────────────────────────────────────────
    for flag_id, flag in RED_FLAGS.items():
        matched_keywords = [kw for kw in flag["keywords"] if kw.lower() in full_text]
        if matched_keywords:
            triggered_flags.append({
                "id"       : flag_id,
                "name"     : flag["name"],
                "slide"    : flag["slide"],
                "severity" : flag["severity"],
                "matched"  : matched_keywords,
                "why_unsafe": flag["description"],
            })
            severity_score += SEVERITY_WEIGHTS.get(flag["severity"], 1)

    # ── Check domain spoofing patterns (slides 12-13) ─────────────────────
    for pattern in SUSPICIOUS_URL_PATTERNS:
        matches = re.findall(pattern, full_text, re.IGNORECASE)
        if matches:
            triggered_urls.extend(matches)

    # ── Check cognitive triggers / psychology (slide 14) ──────────────────
    for trigger_type, keywords in COGNITIVE_TRIGGERS.items():
        matched = [kw for kw in keywords if kw.lower() in full_text]
        if matched:
            triggered_triggers[trigger_type] = matched

    # ── Attachment danger check (slide 15, RF-04) ─────────────────────────
    dangerous_exts = [".iso", ".scr", ".hta", ".vbs", ".exe", ".bat", ".js"]
    attachment      = email.get("attachment") or ""
    dangerous_att   = any(attachment.lower().endswith(ext) for ext in dangerous_exts)
    if dangerous_att:
        severity_score += 4

    # ── Triage Decision (slide 24 decision tree) ──────────────────────────
    if severity_score >= 6 or dangerous_att:
        verdict = "MALICIOUS"
        action  = "BLOCK DOMAIN & ESCALATE TO SECURITY TEAM"
        icon    = "🔴"
    elif severity_score >= 3:
        verdict = "SUSPICIOUS"
        action  = "WARN USER — DO NOT CLICK LINKS OR OPEN ATTACHMENTS"
        icon    = "🟡"
    elif severity_score >= 1:
        verdict = "SUSPICIOUS"
        action  = "WARN USER — VERIFY SENDER VIA OUT-OF-BAND CHANNEL"
        icon    = "🟡"
    else:
        verdict = "SAFE"
        action  = "CLOSE — NO THREATS DETECTED"
        icon    = "🟢"

    return {
        "email_id"          : email["id"],
        "email_type"        : email["type"],
        "sender"            : email["from"],
        "subject"           : email["subject"],
        "attachment"        : attachment or "None",
        "dangerous_att"     : dangerous_att,
        "red_flags"         : triggered_flags,
        "spoofed_urls"      : list(set(triggered_urls)),
        "cognitive_triggers": triggered_triggers,
        "severity_score"    : severity_score,
        "verdict"           : verdict,
        "action"            : action,
        "icon"              : icon,
    }


# =============================================================================
#  SECTION 5 — REPORT FORMATTER
# =============================================================================

def print_report(result: dict) -> None:
    """Prints a detailed analyst triage report for one email."""

    W = 64   # report width

    def rule(char="═"): print(char * W)
    def line(text=""): print(f"  {text}")
    def wrap(text, indent=4):
        for ln in textwrap.wrap(text, width=W - indent):
            print(" " * indent + ln)

    rule()
    print(f"  DECODELABS PHISHING TRIAGE REPORT  |  {result['email_id']}")
    rule()
    line(f"Type      : {result['email_type']}")
    line(f"From      : {result['sender']}")
    line(f"Subject   : {result['subject']}")
    line(f"Attachment: {result['attachment']}"
         + (" ⚠ DANGEROUS EXTENSION" if result['dangerous_att'] else ""))
    rule("─")

    # ── Verdict ───────────────────────────────────────────────────────────
    print(f"\n  {result['icon']}  VERDICT   : {result['verdict']}")
    print(f"  ⚡  SEVERITY  : {result['severity_score']} / 20")
    print(f"  🛡  ACTION    : {result['action']}\n")
    rule("─")

    # ── Red Flags Found ───────────────────────────────────────────────────
    flags = result["red_flags"]
    if flags:
        print(f"\n  RED FLAGS DETECTED ({len(flags)} found):\n")
        for i, flag in enumerate(flags, 1):
            print(f"  [{flag['id']}] {flag['name']}  "
                  f"[{flag['severity']}]  (Slide {flag['slide']})")
            print(f"  Triggered by: {', '.join(repr(k) for k in flag['matched'][:4])}")
            print(f"  WHY UNSAFE:")
            wrap(flag["why_unsafe"], indent=6)
            if i < len(flags):
                print()
    else:
        line("No red flags detected.")

    rule("─")

    # ── Suspicious URLs / Domains ─────────────────────────────────────────
    urls = result["spoofed_urls"]
    if urls:
        print(f"\n  SUSPICIOUS DOMAINS / URL PATTERNS ({len(urls)} found):\n")
        for url in urls:
            print(f"   ⚠  {url}")
        print()
        line("→ Read URLs RIGHT TO LEFT to find the true root domain (Slide 13).")
        line("  e.g., 'microsoft.com.logins-updates.com' — true root = logins-updates.com")

    rule("─")

    # ── Cognitive Triggers ────────────────────────────────────────────────
    triggers = result["cognitive_triggers"]
    if triggers:
        print(f"\n  PSYCHOLOGICAL MANIPULATION TACTICS (Slide 14):\n")
        for ttype, keywords in triggers.items():
            print(f"   {ttype:12s} → {', '.join(repr(k) for k in keywords[:4])}")
        print()
        line("→ These triggers force users to bypass logical verification.")
        line("  Apply the PAUSE → VERIFY → REPORT rule (Slide 18).")

    rule()
    print()


# =============================================================================
#  SECTION 6 — INTERACTIVE ANALYZER
#  User can paste any email text for live analysis
# =============================================================================

def interactive_analyzer() -> None:
    """
    Interactive mode — user can test any email message line by line.

    HOW TO USE:
      - Type or paste a single line / short message and press ENTER to analyze.
      - For multi-line emails: type each line then press ENTER,
        then type a blank line (just press ENTER) to submit.
      - Type 'quit' to exit.
    """

    print("\n" + "=" * 64)
    print("  INTERACTIVE MODE — Test any email or message")
    print("  How to use:")
    print("   • Type or paste text and press ENTER to analyze.")
    print("   • For multi-line emails: press ENTER twice when done.")
    print("   • Type \'quit\' to exit.")
    print("=" * 64 + "\n")

    email_counter = 1

    while True:
        try:
            print(f"  [INPUT #{email_counter}] Enter message text (or \'quit\'):")
            print("  " + "─" * 50)
            lines = []

            while True:
                try:
                    line = input("  > ")
                except EOFError:
                    break

                if line.strip().lower() in ("quit", "exit", "q"):
                    print("\n  Session ended. Stay vigilant. 🛡\n")
                    return

                # Empty line = user is done typing
                if line.strip() == "" and lines:
                    break

                lines.append(line)

            raw_text = "\n".join(lines).strip()

            if not raw_text:
                print("  Nothing entered — try again.\n")
                continue

            # Build email object — try to extract headers if provided
            custom_email = {
                "id"        : f"CUSTOM-{email_counter:02d}",
                "type"      : "User-submitted message",
                "from"      : "",
                "subject"   : "",
                "body"      : raw_text,
                "attachment": "",
            }

            for ln in lines:
                ln_lower = ln.lower().strip()
                if ln_lower.startswith("from:"):
                    custom_email["from"] = ln[5:].strip()
                elif ln_lower.startswith("subject:"):
                    custom_email["subject"] = ln[8:].strip()
                elif ln_lower.startswith("attachment:"):
                    custom_email["attachment"] = ln[11:].strip()

            result = analyze_email(custom_email)
            print_report(result)
            email_counter += 1

        except (KeyboardInterrupt, EOFError):
            print("\n\n  Session ended. Stay vigilant. 🛡\n")
            return


# =============================================================================
#  SECTION 7 — RED FLAG QUICK REFERENCE CARD (Bonus — Conclusion suggestion)
# =============================================================================

def print_red_flag_reference() -> None:
    """Prints a compact Red Flag Checklist — the 'employee checklist' from the conclusion."""

    print("\n" + "=" * 64)
    print("  DECODELABS | RED FLAG QUICK REFERENCE CHECKLIST")
    print("  Batch 2026 — Human Firewall Training Kit")
    print("=" * 64)
    print()
    print("  BEFORE CLICKING ANYTHING, CHECK:\n")
    print("  SENDER")
    print("  [ ] Does the display name match the actual email domain?")
    print("  [ ] Is the domain slightly misspelled? (amaz0n, paypa1)")
    print("  [ ] Is a trusted brand using a free domain? (gmail, yahoo)")
    print()
    print("  CONTENT")
    print("  [ ] Does it create URGENCY or FEAR? (30 min, legal action)")
    print("  [ ] Does it demand SECRECY? (don't discuss, confidential)")
    print("  [ ] Does it request passwords, MFA codes, or payment details?")
    print("  [ ] Does it ask you to CALL a number instead of clicking a link?")
    print("  [ ] Is there an unsolicited QR code to scan?")
    print()
    print("  LINKS")
    print("  [ ] Hover before clicking — does the URL match the brand?")
    print("  [ ] Read the URL RIGHT TO LEFT to find the true root domain")
    print("  [ ] Is it a URL shortener hiding the real destination?")
    print()
    print("  ATTACHMENTS")
    print("  [ ] Is the extension unexpected? (.iso, .hta, .scr, .vbs)")
    print("  [ ] Were you expecting this attachment?")
    print()
    print("  IF IN DOUBT → PAUSE → VERIFY (out-of-band) → REPORT")
    print("  'Never delete a phishing email — REPORT it so IT can")
    print("   purge it from all other inboxes.' (Slide 18)")
    print("=" * 64 + "\n")


# =============================================================================
#  SECTION 8 — MAIN
# =============================================================================

def main() -> None:
    """Runs full analysis on all 5 sample emails, then offers interactive mode."""

    print("\n" + "=" * 64)
    print("  DECODELABS  |  Cyber Security — Project 3")
    print("  Phishing Awareness Analysis  |  Batch 2026")
    print("  The Human Firewall — Threat Detection Engine")
    print("=" * 64)

    print(f"\n  Analyzing {len(SAMPLE_EMAILS)} sample phishing emails...\n")

    summary = []
    for email in SAMPLE_EMAILS:
        result = analyze_email(email)
        print_report(result)
        summary.append(result)

    # ── Summary Table ──────────────────────────────────────────────────────
    print("=" * 64)
    print("  TRIAGE SUMMARY — ALL EMAILS")
    print("=" * 64)
    print(f"  {'ID':<12} {'VERDICT':<12} {'SCORE':<8} {'FLAGS':<8} {'ACTION'}")
    print("  " + "─" * 60)
    for r in summary:
        flags_count = len(r["red_flags"])
        print(f"  {r['email_id']:<12} {r['icon']} {r['verdict']:<10} "
              f"{r['severity_score']:<8} {flags_count:<8} {r['action'][:28]}")

    print("\n" + "=" * 64)
    print(f"  Total Emails Analyzed : {len(summary)}")
    print(f"  Malicious             : {sum(1 for r in summary if r['verdict'] == 'MALICIOUS')}")
    print(f"  Suspicious            : {sum(1 for r in summary if r['verdict'] == 'SUSPICIOUS')}")
    print(f"  Safe                  : {sum(1 for r in summary if r['verdict'] == 'SAFE')}")
    print("=" * 64)

    # ── Red Flag Reference Card ────────────────────────────────────────────
    print_red_flag_reference()

    # ── Interactive Mode ───────────────────────────────────────────────────
    interactive_analyzer()


if __name__ == "__main__":
    main()