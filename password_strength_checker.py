# =============================================================================
#  DecodeLabs Industrial Training Kit | Batch 2026
#  Cyber Security — Project 1: Password Strength Checker
#  Track   : Junior Analyst // Defensive Logic
#  Status  : Submission Ready
# =============================================================================

import string
import hmac   # Used for constant-time comparison (timing-attack safe)


# -----------------------------------------------------------------------------
#  CONSTANTS — Policy Definition (The Zero Point)
# -----------------------------------------------------------------------------

MIN_LENGTH     = 8          # < 8 chars = exponential brute-force risk
SYMBOLS        = set(string.punctuation)   # !@#$%^&*()_+-=[]{}|;:,./<>?

# Common/leaked passwords blacklist (bonus security layer)
COMMON_PASSWORDS = {
    "password", "password1", "12345678", "qwerty123",
    "iloveyou", "admin123", "letmein1", "welcome1",
    "monkey123", "dragon12", "sunshine", "princess"
}


# -----------------------------------------------------------------------------
#  CORE FUNCTION — check_strength()
#  Complexity: O(n) linear scan — validation time grows linearly, not exponentially
# -----------------------------------------------------------------------------

def check_strength(password: str) -> dict:
    """
    Evaluates password strength based on DecodeLabs security policy.

    Args:
        password (str): The raw password string to evaluate.

    Returns:
        dict: Contains 'level' (Weak/Medium/Strong), 'score' (0-4),
              'criteria' (breakdown), and 'feedback' (improvement tips).
    """

    # --- Guard: empty input ---
    if not password:
        return {
            "level"    : "Invalid",
            "score"    : 0,
            "criteria" : {},
            "feedback" : ["Password cannot be empty."]
        }

    # -------------------------------------------------------------------------
    #  PATTERN RECOGNITION — Pythonic any() approach (C-optimised, short-circuit)
    #  The Professional approach from slide 9: NOT manual for-loops
    # -------------------------------------------------------------------------

    has_length  = len(password) >= MIN_LENGTH
    has_upper   = any(c.isupper()      for c in password)   # [A-Z] check
    has_digit   = any(c.isdigit()      for c in password)   # [0-9] check
    has_symbol  = any(c in SYMBOLS     for c in password)   # symbol check
    has_lower   = any(c.islower()      for c in password)   # [a-z] check (bonus)

    # Bonus: leaked password check (constant-time via hmac to prevent timing attacks)
    is_common = any(
        hmac.compare_digest(password.lower(), common)
        for common in COMMON_PASSWORDS
    )

    # -------------------------------------------------------------------------
    #  SCORING — each criterion contributes +1 (max score = 4)
    # -------------------------------------------------------------------------

    criteria = {
        "Length >= 8"       : has_length,
        "Uppercase [A-Z]"   : has_upper,
        "Digit [0-9]"       : has_digit,
        "Symbol !@#$..."    : has_symbol,
    }

    score = sum(criteria.values())   # sum([True, False, True, True]) = 3

    # -------------------------------------------------------------------------
    #  CLASSIFICATION — The Gatekeeper Rule
    #  "You cannot hash what is weak. Filter entropy before Argon2id." — Slide 12
    # -------------------------------------------------------------------------

    if not has_length or score <= 1 or is_common:
        level = "Weak"
    elif score == 2 or score == 3:
        level = "Medium"
    else:   # score == 4
        level = "Strong"

    # -------------------------------------------------------------------------
    #  FEEDBACK — actionable improvement tips
    # -------------------------------------------------------------------------

    feedback = []

    if not has_length:
        feedback.append(f"Too short — use at least {MIN_LENGTH} characters.")
    if not has_upper:
        feedback.append("Add at least one uppercase letter [A-Z].")
    if not has_digit:
        feedback.append("Add at least one digit [0-9].")
    if not has_symbol:
        feedback.append("Add at least one symbol e.g. !@#$%^&*")
    if is_common:
        feedback.append("This password appears in common/leaked password lists — choose something unique.")
    if level == "Strong":
        feedback.append("All criteria met. Gatekeeper PASS — ready for hashing.")

    return {
        "level"    : level,
        "score"    : score,
        "criteria" : criteria,
        "feedback" : feedback,
        "flagged"  : is_common
    }


# -----------------------------------------------------------------------------
#  DISPLAY FUNCTION — formats results for terminal output
# -----------------------------------------------------------------------------

def display_result(password: str, result: dict) -> None:
    """Prints a formatted strength report for a given password."""

    ICONS   = {"Weak": "🔴", "Medium": "🟡", "Strong": "🟢", "Invalid": "⚪"}
    BARS    = {"Weak": "██░░░░░░", "Medium": "█████░░░", "Strong": "████████", "Invalid": "░░░░░░░░"}

    level   = result["level"]
    score   = result["score"]
    icon    = ICONS.get(level, "⚪")
    bar     = BARS.get(level, "░░░░░░░░")

    # Mask the password for display (security best practice)
    masked = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "***"

    print("\n" + "─" * 52)
    print(f"  Password  : {masked}")
    print(f"  Strength  : {icon}  {level.upper()}   {bar}  ({score}/4)")
    print("  ─" * 26)
    print("  Criteria Breakdown:")
    for criterion, passed in result["criteria"].items():
        status = "✔" if passed else "✘"
        print(f"    [{status}]  {criterion}")
    if result.get("flagged"):
        print("  ⚠  Flagged in common passwords list")
    print("  ─" * 26)
    print("  Feedback:")
    for tip in result["feedback"]:
        print(f"    →  {tip}")
    print("─" * 52)


# -----------------------------------------------------------------------------
#  MAIN — Interactive CLI + Test Suite
# -----------------------------------------------------------------------------

def run_test_suite() -> None:
    """Runs a built-in test suite to verify checker logic."""

    print("\n" + "=" * 52)
    print("  DECODELABS | Defensive Logic — Test Suite")
    print("=" * 52)

    test_cases = [
        # (password,          expected_level)
        ("abc",               "Weak"),      # too short
        ("password",          "Weak"),      # common password
        ("longenough1",       "Medium"),    # length + digit, no symbol/upper
        ("LongEnough1",       "Medium"),    # length + digit + upper, no symbol
        ("Pass@1234",         "Strong"),    # all 4 criteria
        ("Tr0ub4dor&3",       "Strong"),    # classic XKCD-style strong
        ("",                  "Invalid"),   # empty
    ]

    passed = 0
    for pw, expected in test_cases:
        result  = check_strength(pw)
        actual  = result["level"]
        status  = "PASS" if actual == expected else "FAIL"
        if status == "PASS":
            passed += 1
        flag    = " ⚠ (common)" if result.get("flagged") else ""
        display = (pw[:12] + "...") if len(pw) > 12 else pw
        print(f"  [{status}]  {display:<18s}  →  {actual}{flag}")

    print("─" * 52)
    print(f"  Results: {passed}/{len(test_cases)} tests passed")
    print("=" * 52)


def main() -> None:
    """Entry point — interactive mode with test suite."""

    print("\n" + "=" * 52)
    print("  DECODELABS  |  Cyber Security — Project 1")
    print("  Password Strength Checker  |  Batch 2026")
    print("=" * 52)

    # Run built-in test suite first
    run_test_suite()

    # Interactive mode
    print("\n  [ Interactive Mode — type 'quit' to exit ]\n")

    while True:
        try:
            raw = input("  Enter password: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  Session ended. Stay secure.\n")
            break

        if raw.lower() in ("quit", "exit", "q"):
            print("\n  Session ended. Stay secure.\n")
            break

        result = check_strength(raw)
        display_result(raw, result)


# -----------------------------------------------------------------------------
#  Entry Point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    main()
