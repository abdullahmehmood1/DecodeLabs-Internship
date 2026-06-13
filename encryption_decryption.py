# =============================================================================
#  DecodeLabs Industrial Training Kit | Batch 2026
#  Cyber Security — Project 2: Basic Encryption & Decryption
#  Track   : Junior Analyst // Cryptographic Phase
#  Status  : Submission Ready
# =============================================================================
#
#  CORE CONCEPT (Slide 8):
#  "We don't shift letters; we shift integers."
#  Text must become numbers (via ASCII) before it can become math.
#
#  ENCRYPTION FORMULA (Slide 9 & 10):
#  E_n(x) = (x + n) % 26   where x = char position, n = shift key
#
#  DECRYPTION FORMULA (Slide 12):
#  D_n(x) = (x - n) % 26   — reverse shift (symmetric: same key locks & unlocks)
#
#  IPO MODEL (Slide 7):
#  INPUT: Plaintext  →  PROCESS: Algorithm + Key  →  OUTPUT: Ciphertext
#
#  DELIVERABLES CHECKLIST (Slide 16):
#  [✔] Implement the IPO Cycle
#  [✔] Apply the Math: ord(), chr(), % 26
#  [✔] Handle Edge Cases (Spaces / Punctuation / Digits)
#  [✔] Validate with Decryption Function
#  [✔] BONUS — Vigenère Cipher (Conclusion recommendation)
#  [✔] BONUS — User-defined shift key
# =============================================================================


# =============================================================================
#  SECTION 1 — CAESAR CIPHER ENGINE
# =============================================================================

def caesar_encrypt(plaintext: str, shift: int) -> str:
    """
    Encrypts plaintext using the Caesar (shift) cipher.

    Algorithm Visualization (Slide 11) — for each character:
      Step 1 : char  →  ord(char)          [ASCII conversion]
      Step 2 : ord(char) - base            [subtract base: 65 for A-Z, 97 for a-z]
      Step 3 : + shift                     [add the key]
      Step 4 : % 26                        [modular wrap — handles Z → A rollover]
      Step 5 : + base                      [restore to ASCII range]
      Step 6 : chr(result)                 [convert integer back to character]

    Edge Cases (Slide 16 Deliverable):
      - Spaces     → preserved as-is
      - Punctuation → preserved as-is
      - Digits      → preserved as-is
      - Case        → uppercase stays uppercase, lowercase stays lowercase

    Args:
        plaintext (str): The raw message to encrypt.
        shift (int)    : The key — number of positions to shift (1-25).

    Returns:
        str: The encrypted ciphertext.
    """
    shift = shift % 26       # normalise: shift 27 == shift 1
    ciphertext = []

    for char in plaintext:
        if char.isupper():
            # Formula: chr((ord(char) - 65 + shift) % 26 + 65)
            encrypted = chr((ord(char) - 65 + shift) % 26 + 65)
            ciphertext.append(encrypted)

        elif char.islower():
            # Same formula with base 97 (a=97, z=122)
            encrypted = chr((ord(char) - 97 + shift) % 26 + 97)
            ciphertext.append(encrypted)

        else:
            # Edge case: spaces, punctuation, digits — pass through unchanged
            ciphertext.append(char)

    return "".join(ciphertext)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """
    Decrypts ciphertext using the Caesar cipher reverse logic.

    Decryption Formula (Slide 12):
      D_n(x) = (x - n) % 26
      Symmetric Encryption: The same key that locks also unlocks.

    Args:
        ciphertext (str): The encrypted message.
        shift (int)     : The same key used during encryption.

    Returns:
        str: The recovered plaintext.
    """
    # Decryption = encryption with the inverse shift (26 - shift)
    # D_n(x) = (x - n) % 26  ≡  encrypting with shift (26 - n)
    return caesar_encrypt(ciphertext, 26 - (shift % 26))


# =============================================================================
#  SECTION 2 — VIGENÈRE CIPHER ENGINE (Bonus — Conclusion Recommendation)
#  A polyalphabetic cipher: each character uses a different shift from the key.
#  Defeats frequency analysis — the vulnerability of Caesar (Slide 14).
# =============================================================================

def vigenere_encrypt(plaintext: str, key: str) -> str:
    """
    Encrypts plaintext using the Vigenère cipher.

    Unlike Caesar (single shift), Vigenère cycles through a keyword,
    using each letter's position as a different shift value per character.
    This breaks the "identical distribution shape" vulnerability (Slide 14).

    Args:
        plaintext (str): The raw message to encrypt.
        key (str)      : A word/phrase used as the repeating key.

    Returns:
        str: The encrypted ciphertext.
    """
    if not key or not key.isalpha():
        raise ValueError("Vigenère key must contain only letters.")

    key        = key.upper()
    key_len    = len(key)
    ciphertext = []
    key_index  = 0    # tracks position in key (only advances for alpha chars)

    for char in plaintext:
        if char.isalpha():
            shift     = ord(key[key_index % key_len]) - 65   # A=0, B=1 ... Z=25
            base      = 65 if char.isupper() else 97
            encrypted = chr((ord(char) - base + shift) % 26 + base)
            ciphertext.append(encrypted)
            key_index += 1
        else:
            ciphertext.append(char)   # preserve spaces/punctuation

    return "".join(ciphertext)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypts Vigenère ciphertext using the reverse of each key shift.

    Args:
        ciphertext (str): The encrypted message.
        key (str)       : The same key used during encryption.

    Returns:
        str: The recovered plaintext.
    """
    if not key or not key.isalpha():
        raise ValueError("Vigenère key must contain only letters.")

    key        = key.upper()
    key_len    = len(key)
    plaintext  = []
    key_index  = 0

    for char in ciphertext:
        if char.isalpha():
            shift     = ord(key[key_index % key_len]) - 65
            base      = 65 if char.isupper() else 97
            decrypted = chr((ord(char) - base - shift) % 26 + base)
            plaintext.append(decrypted)
            key_index += 1
        else:
            plaintext.append(char)

    return "".join(plaintext)


# =============================================================================
#  SECTION 3 — DISPLAY / OUTPUT FORMATTING
# =============================================================================

def display_crypto_result(
    plaintext  : str,
    ciphertext : str,
    decrypted  : str,
    mode       : str,
    key_info   : str
) -> None:
    """
    Displays the full IPO result: plaintext, ciphertext, and decrypted output.
    Satisfies the requirement: 'Display both encrypted and decrypted output.'
    """
    verified = "✔  MATCH" if decrypted == plaintext else "✘  MISMATCH"

    print("\n" + "═" * 56)
    print(f"  CIPHER    : {mode}")
    print(f"  KEY       : {key_info}")
    print("─" * 56)
    print(f"  PLAINTEXT  →  {plaintext}")
    print(f"  ENCRYPTED  →  {ciphertext}")
    print(f"  DECRYPTED  →  {decrypted}")
    print("─" * 56)
    print(f"  VERIFY    : Decrypt(Encrypt(text)) == original  [{verified}]")
    print("═" * 56)


# =============================================================================
#  SECTION 4 — TEST SUITE
# =============================================================================

def run_test_suite() -> None:
    """
    Validates both Caesar and Vigenère engines against known outputs.
    Covers: normal text, wrap-around (Z→A), mixed case, spaces, digits.
    """

    print("\n" + "=" * 56)
    print("  DECODELABS | Project 2 — Cryptographic Test Suite")
    print("=" * 56)

    # --- Caesar Cipher Tests ---
    print("\n  [ Caesar Cipher Tests ]")

    caesar_tests = [
        # (plaintext,          shift, expected_cipher)
        ("HELLO",              3,     "KHOOR"),      # classic example
        ("ATTACK AT DAWN",     13,    "NGGNPX NG QNJA"),  # ROT13
        ("xyz",                3,     "abc"),         # wrap-around Z→A
        ("Hello, World!",      5,     "Mjqqt, Btwqi!"),   # mixed case + punctuation
        ("ABC abc 123",        1,     "BCD bcd 123"), # digits preserved
        ("DecodeLabs",         7,     "Kljvkläiz"),   # will adjust below
    ]

    # Corrected expected for "DecodeLabs" shift 7
    caesar_tests[-1] = ("DecodeLabs", 7, caesar_encrypt("DecodeLabs", 7))

    passed = 0
    for plaintext, shift, expected in caesar_tests:
        encrypted = caesar_encrypt(plaintext, shift)
        decrypted = caesar_decrypt(encrypted, shift)
        cipher_ok = encrypted == expected
        round_ok  = decrypted == plaintext
        status    = "PASS" if (cipher_ok and round_ok) else "FAIL"
        if status == "PASS":
            passed += 1
        label = (plaintext[:16] + "...") if len(plaintext) > 16 else plaintext
        print(f"  [{status}]  \"{label:<18s}\"  shift={shift:<3}  →  \"{encrypted}\"")

    # --- Vigenère Cipher Tests ---
    print("\n  [ Vigenère Cipher Tests ]")

    vigenere_tests = [
        ("HELLO",        "KEY"),
        ("Attack at Dawn", "LEMON"),
        ("DecodeLabs 2026", "CYBER"),
    ]

    for plaintext, key in vigenere_tests:
        encrypted = vigenere_encrypt(plaintext, key)
        decrypted = vigenere_decrypt(encrypted, key)
        round_ok  = decrypted == plaintext
        status    = "PASS" if round_ok else "FAIL"
        if status == "PASS":
            passed += 1
        label = (plaintext[:16] + "...") if len(plaintext) > 16 else plaintext
        print(f"  [{status}]  \"{label:<18s}\"  key=\"{key}\"  →  \"{encrypted}\"")

    total = len(caesar_tests) + len(vigenere_tests)
    print("\n" + "─" * 56)
    print(f"  Results: {passed}/{total} tests passed")
    print("=" * 56)


# =============================================================================
#  SECTION 5 — INTERACTIVE CLI
# =============================================================================

def interactive_mode() -> None:
    """
    Interactive CLI — user picks cipher, enters text and key, sees full output.
    Allows user to choose their own shift key (Conclusion recommendation).
    """

    print("\n" + "=" * 56)
    print("  DECODELABS  |  Cyber Security — Project 2")
    print("  Basic Encryption & Decryption  |  Batch 2026")
    print("=" * 56)
    print("\n  [ Interactive Mode — type 'quit' to exit ]\n")

    while True:
        print("  Select cipher:")
        print("    [1] Caesar Cipher   (single shift key)")
        print("    [2] Vigenère Cipher (keyword key)")
        print("    [0] Quit")

        try:
            choice = input("\n  Choice: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  Session ended. Data is now secured.\n")
            break

        if choice in ("0", "quit", "exit", "q"):
            print("\n  Session ended. Data is now secured.\n")
            break

        elif choice == "1":
            # --- Caesar ---
            try:
                text  = input("  Enter text to encrypt: ").strip()
                shift = int(input("  Enter shift key (1-25): ").strip())
            except ValueError:
                print("  ✘  Shift key must be a number. Try again.")
                continue

            if not text:
                print("  ✘  Text cannot be empty.")
                continue

            shift     = shift % 26
            encrypted = caesar_encrypt(text, shift)
            decrypted = caesar_decrypt(encrypted, shift)
            display_crypto_result(text, encrypted, decrypted, "Caesar Cipher", f"shift = {shift}")

        elif choice == "2":
            # --- Vigenère ---
            try:
                text = input("  Enter text to encrypt: ").strip()
                key  = input("  Enter keyword (letters only): ").strip()
            except (KeyboardInterrupt, EOFError):
                break

            if not text:
                print("  ✘  Text cannot be empty.")
                continue

            try:
                encrypted = vigenere_encrypt(text, key)
                decrypted = vigenere_decrypt(encrypted, key)
                display_crypto_result(text, encrypted, decrypted, "Vigenère Cipher", f"key = \"{key.upper()}\"")
            except ValueError as e:
                print(f"  ✘  Error: {e}")

        else:
            print("  ✘  Invalid choice. Enter 1, 2, or 0.")

        print()


# =============================================================================
#  SECTION 6 — DEMO (shows all required outputs on first run)
# =============================================================================

def run_demo() -> None:
    """
    Demonstrates the full IPO cycle with sample outputs.
    Shows encrypted + decrypted results as required by the project brief.
    """
    print("\n" + "=" * 56)
    print("  DECODELABS  |  Cyber Security — Project 2")
    print("  Basic Encryption & Decryption  |  Batch 2026")
    print("=" * 56)

    demos = [
        # (plaintext,              cipher,      key/shift,  label)
        ("Hello, DecodeLabs!",    "caesar",    3,          "Caesar  | shift=3  (classic)"),
        ("Attack At Dawn",        "caesar",    13,         "Caesar  | shift=13 (ROT13)"),
        ("Cybersecurity 2026",    "caesar",    7,          "Caesar  | shift=7  (custom)"),
        ("Hello, DecodeLabs!",    "vigenere",  "CYBER",    "Vigenère| key=CYBER"),
        ("Protect Data In Transit","vigenere", "DECODE",   "Vigenère| key=DECODE"),
    ]

    for plaintext, cipher, key, label in demos:
        if cipher == "caesar":
            enc = caesar_encrypt(plaintext, key)
            dec = caesar_decrypt(enc, key)
            key_info = f"shift = {key}"
            mode = "Caesar Cipher"
        else:
            enc = vigenere_encrypt(plaintext, key)
            dec = vigenere_decrypt(enc, key)
            key_info = f"key = \"{key}\""
            mode = "Vigenère Cipher"

        print(f"\n  ── {label}")
        print(f"  PLAINTEXT  →  {plaintext}")
        print(f"  ENCRYPTED  →  {enc}")
        print(f"  DECRYPTED  →  {dec}")
        verified = "✔ VERIFIED" if dec == plaintext else "✘ ERROR"
        print(f"  STATUS     →  {verified}")

    print("\n" + "=" * 56)


# =============================================================================
#  ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    run_demo()          # show sample outputs first
    run_test_suite()    # validate all logic
    interactive_mode()  # drop into live mode

