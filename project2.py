"""
MORROW 1.0 - Scam Awareness Trainer
=====================================
CampusShield - Feature 1: Message & Link Risk Scanner
Core idea: don't just flag scam messages, TEACH the user why it's a scam.
Two modes: (1) Analyze a message the user pastes in
           (2) Quiz mode - show real scam examples, test if user can spot them
"""

import re


# ============================================================
# STEP 1: THE RED FLAG RULEBOOK
# ============================================================
# Structure: category_name -> list of (regex_pattern, plain_english_explanation)
# Expanded using Goa NCRB 2024 data + Herald Goa / Incredible Goa scam
# reporting (digital arrest, task scams, investment scams, job scams).

RED_FLAGS = {
    "urgency": [
        (r"\bimmediately\b", "creates false time pressure so you act without thinking"),
        (r"\bwithin 24 hours\b", "creates false time pressure so you act without thinking"),
        (r"\bblocked\b", "threatens loss of access to scare you into reacting fast"),
        (r"\baccount (will be )?suspend(ed)?\b", "threatens account loss to force a fast, panicked reaction"),
        (r"\blast warning\b", "false final-notice pressure - real institutions don't operate this way"),
        (r"\burgent(ly)?\b", "manufactured urgency is the single most common scam trigger"),
        (r"\bact now\b", "pushes you to skip verification and act on impulse"),
        (r"\bexpire[sd]? (today|soon)\b", "fake deadline designed to prevent you from checking with anyone"),
    ],
    "fake_authority": [
        (r"\bCBI\b", "impersonates a law enforcement agency - real agencies don't contact you like this"),
        (r"\bRBI\b", "impersonates India's central bank - RBI never calls individuals directly"),
        (r"\bcustoms\b", "impersonates a government body to sound official"),
        (r"\bdigital arrest\b", "this is NOT a real legal term - no such thing exists in Indian law"),
        (r"\bincome tax\b", "impersonates a tax authority to create fear of legal trouble"),
        (r"\bpolice (station|officer|department)\b", "impersonates police - genuine police do not settle cases over call/WhatsApp"),
        (r"\bmagistrate\b", "impersonates judiciary to fabricate legal legitimacy"),
        (r"\barrest warrant\b", "fabricated document - real warrants are never served by phone or video call"),
        (r"\bmoney laundering\b", "false accusation used to frighten victims into compliance"),
        (r"\bAadhaar (card )?(linked|suspended|blocked)\b", "fake claim that ID documents are linked to crime, to induce panic"),
    ],
    "money_request": [
        (r"\bOTP\b", "no legitimate service ever asks you to share an OTP"),
        (r"\bUPI PIN\b", "you never need to enter your PIN to RECEIVE money, only to send it"),
        (r"\brefund\b", "refund scams trick you into approving a payment, not receiving one"),
        (r"\bKYC\b", "fake KYC update requests are a top vector for credential theft"),
        (r"\bverify (your )?account\b", "generic pretext to extract banking details or credentials"),
        (r"\bcollect request\b", "a payment collect request approval sends YOUR money out, not in"),
        (r"\bprocessing fee\b", "legitimate jobs/visas never require upfront fees before any offer is real"),
        (r"\bsecurity (check|deposit)\b", "fabricated fee scammers use to extract money under fear of arrest"),
        (r"\bregistration fee\b", "common in fake job/task scams before the scammer disappears"),
        (r"\bdouble your (money|investment)\b", "guaranteed high returns are the hallmark of investment fraud"),
    ],
    "suspicious_link": [
        (r"bit\.ly", "shortened links hide the real destination website"),
        (r"tinyurl", "shortened links hide the real destination website"),
        (r"\bQR code\b", "fake QR codes can silently trigger payment/authorization instead of receiving money"),
        (r"\bclick here\b", "vague call-to-action link text, common in phishing"),
        (r"forms\.gle|docs\.google\.com/forms", "scammers commonly clone real institutions using free Google Forms"),
    ],
    "job_investment_bait": [
        (r"\bwork from home\b", "common framing for task-based and fake employment scams"),
        (r"\blike (this )?video\b", "task-based scam pattern - small paid tasks build trust before a large deposit demand"),
        (r"\bearn (up to )?(rs\.?|₹|inr)\s?\d+", "unrealistic guaranteed-earning claims are a classic bait pattern"),
        (r"\bcrypto(currency)?\b", "high-return crypto pitches from unknown senders are a leading fraud category"),
        (r"\bvisa fee\b", "foreign job scams demand fees before any real offer or interview exists"),
        (r"\bpart[- ]?time job\b", "frequently used as bait framing in task-based and WhatsApp job scams"),
    ],
}
# REMINDER: keep this rulebook DATA, not logic. Judges will like seeing
# how easy it is to add new scam patterns without touching the code.


# ============================================================
# STEP 2: THE SCORING + EXPLAINING ENGINE
# ============================================================

def score_message(text):
    """
    Takes a message string, returns:
      - total_score (int)
      - matched_flags (list of (category, explanation) tuples)
    """
    score = 0
    matched_flags = []
    for category, pattern_list in RED_FLAGS.items():
        for pattern, explanation in pattern_list:
            if re.search(pattern, text, re.IGNORECASE):
                score += 1
                matched_flags.append((category, explanation))
    return score, matched_flags


def risk_level(score):
    """
    Turns a raw score into a human label + a rough percentage,
    so it lines up with the app's Tier 1 (>=50%) / Tier 2 (<=40%)
    design from the CampusShield spec.
    """
    if score == 0:
        return "Looks safe", 0
    elif score <= 2:
        return "Some caution advised", 40
    else:
        # cap the display percentage at 95 so it never claims total certainty
        pct = min(50 + (score - 3) * 10, 95)
        return "High risk - likely a scam", pct


def explain_flags(matched_flags):
    """
    Takes the matched_flags list from score_message() and returns
    a readable explanation block.
    """
    if not matched_flags:
        return "No red flags detected."

    lines = []
    for category, explanation in matched_flags:
        label = category.replace("_", " ").title()
        lines.append(f"- [{label}] {explanation}")
    return "\n".join(lines)


# ============================================================
# STEP 3: QUIZ MODE (this is your demo showpiece)
# ============================================================
# Built from real Goa scam patterns reported in 2025-2026 (Herald Goa,
# Incredible Goa, NCRB 2024 data). Messages are rephrased, not copied
# verbatim from the news reports, to keep them original examples.

QUIZ_BANK = [
    {
        "text": "This is Insp. Rajeev Sharma, Mumbai Crime Branch. Your Aadhaar is linked to a money laundering case. You are under digital arrest. Do not disconnect this call or share details with family. Transfer funds immediately for verification or a warrant will be issued.",
        "is_scam": True,
        "explanation": "Classic digital arrest scam - fake police identity, isolation tactic ('don't tell family'), fabricated legal threat, and urgent money demand. 'Digital arrest' is not a real legal process in India.",
    },
    {
        "text": "Hi, this is Parul University Exam Cell. Your semester exam hall ticket is ready for download in the student portal under the Downloads tab. Contact your department office if you face login issues.",
        "is_scam": False,
        "explanation": "No urgency, no money or OTP request, no suspicious external link - directs you to the official portal you already use.",
    },
    {
        "text": "CONGRATULATIONS! You are selected for a work from home job, earn Rs 5000/day liking YouTube videos. Join our Telegram group now, first task pays instantly. Small registration fee of Rs 199 to activate your account.",
        "is_scam": True,
        "explanation": "Task-based scam: unrealistic guaranteed daily income, upfront registration fee, and a small 'first task pays instantly' hook used to build trust before bigger deposit demands.",
    },
    {
        "text": "Your food delivery order #4521 has been placed. Estimated delivery in 25 minutes. Track your order in the app.",
        "is_scam": False,
        "explanation": "Routine transactional notification with no request for money, OTP, or personal information.",
    },
    {
        "text": "URGENT: Your bank KYC has expired and your account will be blocked within 24 hours. Click here to update: bit.ly/kyc-verify-now and enter your UPI PIN to reactivate.",
        "is_scam": True,
        "explanation": "Combines false urgency, a fake KYC deadline, a shortened suspicious link, and a request for your UPI PIN - which is never needed to receive or verify anything.",
    },
    {
        "text": "Reminder: Your library book 'Introduction to Algorithms' is due tomorrow. Renew online or return it at the campus library to avoid a late fee of Rs 5/day.",
        "is_scam": False,
        "explanation": "Plausible, low-stakes campus notification with a small stated fee amount and no link, OTP, or payment request.",
    },
    {
        "text": "Double your investment in 30 days! Join our exclusive crypto trading group. Early investors are already seeing 40% returns. Limited slots, invest before slots close today.",
        "is_scam": True,
        "explanation": "Investment scam pattern: guaranteed impossible returns, fake scarcity ('limited slots'), and pressure to act before you can research or verify the scheme.",
    },
    {
        "text": "Placement Cell Notice: TCS campus drive registration closes Friday 5 PM. Register via the official placement portal link shared in the department WhatsApp group by your Training & Placement Officer.",
        "is_scam": False,
        "explanation": "Has a deadline, but it's tied to a known official process, a named responsible person, and no direct money or credential request.",
    },
    {
        "text": "Foreign Job Opportunity - Germany, salary 3 lakh/month, immediate joining. Pay Rs 15,000 visa processing fee to confirm your seat, only 3 seats left.",
        "is_scam": True,
        "explanation": "Foreign job scam: unrealistic salary, upfront visa fee before any real interview or offer letter, and fake scarcity to rush the decision.",
    },
    {
        "text": "Hey, it's Divya from 3rd year CS. We're collecting feedback forms for the coding club, can you fill this Google Form when free? No rush, just need it before the club meeting next week.",
        "is_scam": True,
        "explanation": "This mirrors the real Parul University 'fake senior' pattern - an unfamiliar name posing as a senior, using a casual tone and a Google Form to lower suspicion. Always verify the sender's identity through official channels before filling any form, even low-pressure ones.",
    },
]


def run_quiz():
    """
    Loops through QUIZ_BANK, shows each message, asks user to guess
    scam or safe, tracks score, reveals the explanation either way.
    """
    correct_count = 0
    total = len(QUIZ_BANK)

    print("\n=== SCAM AWARENESS QUIZ ===")
    print(f"{total} messages. For each one, decide: Scam or Safe?\n")

    for i, item in enumerate(QUIZ_BANK, start=1):
        print(f"--- Message {i}/{total} ---")
        print(f'"{item["text"]}"\n')

        answer = input("Scam or Safe? (s/f): ").strip().lower()
        user_says_scam = answer.startswith("s")

        if user_says_scam == item["is_scam"]:
            correct_count += 1
            print("Correct!")
        else:
            print("Not quite.")

        verdict = "SCAM" if item["is_scam"] else "SAFE"
        print(f"[{verdict}] {item['explanation']}\n")

    print(f"=== Final score: {correct_count}/{total} ===\n")


# ============================================================
# STEP 4: MAIN MENU (glue code)
# ============================================================

def main():
    print("=" * 50)
    print("  MORROW 1.0 - Scam Awareness Trainer")
    print("  CampusShield Feature 1: Risk Scanner")
    print("=" * 50)

    while True:
        print("\n1. Analyze a message")
        print("2. Take the awareness quiz")
        print("3. Exit")
        choice = input("\nChoose an option (1-3): ").strip()

        if choice == "1":
            text = input("\nPaste the message to analyze:\n> ")
            score, matched_flags = score_message(text)
            level, pct = risk_level(score)

            print(f"\nRisk score: {score}")
            print(f"Verdict: {level} (~{pct}% risk)")
            print("\nReasons:")
            print(explain_flags(matched_flags))

        elif choice == "2":
            run_quiz()

        elif choice == "3":
            print("\nStay safe. Exiting.")
            break

        else:
            print("Invalid choice, pick 1, 2, or 3.")


if __name__ == "__main__":
    main()