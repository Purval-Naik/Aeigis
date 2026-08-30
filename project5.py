"""
MORROW 1.2 - Scam Awareness Trainer
=====================================
/ Aegis - Feature 1: Message & Link Risk Scanner
Core idea: don't just flag scam messages, TEACH the user why it's a scam.
Two modes: (1) Analyze a message the user pastes in
           (2) Quiz mode - show real scam examples, test if user can spot them

CHANGELOG (1.1 -> 1.2):
- QUIZ_BANK expanded from 11 to 30 questions, covering scam types that
  weren't represented before (romance, fake delivery/customs fee, lottery,
  fake internship stipend, SIM swap, fake fee refund, fake exam result
  phishing, and more).
- run_quiz() now picks a random sample of 10 questions per run (no
  repeats within a run) instead of always running the full bank in
  the same order. Score display is now dynamic ("X/10") instead of
  hardcoded, so it stays correct if QUIZ_SAMPLE_SIZE changes later.

CHANGELOG (1.0 -> 1.1):
- Category weighting: fake_authority / money_request count for more than
  urgency / suspicious_link, because that's what real scams combo on.
- "part-time job" no longer scores on its own (too many false positives
  on real campus job postings) - it now only counts when paired with
  at least one other flag.
- risk_level() rewritten around weighted score, not raw match count,
  so the Tier 1 / Tier 2 cutoffs actually mean something explainable.
"""

import random
import re
import time


# ============================================================
# STEP 0: LOADING ANIMATION (small UX touch for the demo)
# ============================================================
# Purely cosmetic - makes the CLI feel less instant/robotic when
# "analyzing" a message or starting the quiz. Doesn't affect scoring.

def loading_animation(message="Analyzing", dots=3, delay=0.4):
    """
    Prints `message` followed by `dots` dots appearing one at a time,
    then moves to a new line. e.g. loading_animation("Analyzing")
    prints: Analyzing... (with a short pause before each dot)
    """
    print(message, end="", flush=True)
    for _ in range(dots):
        time.sleep(delay)
        print(".", end="", flush=True)
    print()  # newline once the animation finishes


# ============================================================
# STEP 1: THE RED FLAG RULEBOOK
# ============================================================
# Structure: category_name -> (weight, list of (regex_pattern, explanation))
# Weight = how dangerous a match in this category is on its own.
# fake_authority and money_request are the categories real scams
# almost always need to close the loop, so they weigh more.

RED_FLAGS = {
    "urgency": {
        "weight": 1,
        "patterns": [
            (r"\bimmediately\b", "creates false time pressure so you act without thinking"),
            (r"\bwithin 24 hours\b", "creates false time pressure so you act without thinking"),
            (r"\bblocked\b", "threatens loss of access to scare you into reacting fast"),
            (r"\baccount (will be )?suspend(ed)?\b", "threatens account loss to force a fast, panicked reaction"),
            (r"\blast warning\b", "false final-notice pressure - real institutions don't operate this way"),
            (r"\burgent(ly)?\b", "manufactured urgency is the single most common scam trigger"),
            (r"\bact now\b", "pushes you to skip verification and act on impulse"),
            (r"\bexpire[sd]? (today|soon)\b", "fake deadline designed to prevent you from checking with anyone"),
            (r"\bdisconnect(ed)? (in|within) \d+ (hour|minute)", "artificially short countdown designed to force a rushed payment"),
        ],
    },
    "fake_authority": {
        "weight": 3,
        "patterns": [
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
    },
    "money_request": {
        "weight": 3,
        "patterns": [
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
    },
    "suspicious_link": {
        "weight": 2,
        "patterns": [
            (r"bit\.ly", "shortened links hide the real destination website"),
            (r"tinyurl", "shortened links hide the real destination website"),
            (r"\bQR code\b", "fake QR codes can silently trigger payment/authorization instead of receiving money"),
            (r"\bclick here\b", "vague call-to-action link text, common in phishing"),
            (r"forms\.gle|docs\.google\.com/forms", "scammers commonly clone real institutions using free Google Forms"),
            (r"\.tk\b|\.ml\b|\.ga\b|\.cf\b", "free, unregulated domain extensions are heavily favored by scam sites since they require no verification to register"),
        ],
    },
    "job_investment_bait": {
        "weight": 2,
        "patterns": [
            (r"\bwork from home\b", "common framing for task-based and fake employment scams"),
            (r"\blike (this )?video\b", "task-based scam pattern - small paid tasks build trust before a large deposit demand"),
            (r"\bearn (up to )?(rs\.?|₹|inr)\s?\d+", "unrealistic guaranteed-earning claims are a classic bait pattern"),
            (r"\bcrypto(currency)?\b", "high-return crypto pitches from unknown senders are a leading fraud category"),
            (r"\bvisa fee\b", "foreign job scams demand fees before any real offer or interview exists"),
        ],
    },
    # Split out from job_investment_bait: this pattern alone is too common
    # in real, legitimate campus job postings to score on its own. It only
    # counts if at least one other flag (any category) also matched -
    # see the "conditional" handling in score_message().
    "job_conditional": {
        "weight": 1,
        "patterns": [
            (r"\bpart[- ]?time job\b", "vague part-time job framing - only suspicious when combined with other red flags"),
        ],
    },
}
# REMINDER: keep this rulebook DATA, not logic. Judges will like seeing
# how easy it is to add new scam patterns without touching the code.


# ============================================================
# STEP 2: THE SCORING + EXPLAINING ENGINE
# ============================================================

def score_message(text):
    """
    Takes a message string, returns:
      - total_score (int, weighted)
      - matched_flags (list of (category, weight, explanation) tuples)

    Weighted scoring: each match contributes its category's weight,
    not a flat 1 point. fake_authority and money_request matches count
    for 3x an urgency-only match, because real scams need those two
    categories to actually extract money - urgency alone is just noise.

    job_conditional (currently just "part-time job") is held back and
    only added to the score if something else matched first. This kills
    the false positive on genuine part-time job postings while still
    letting it add weight to an already-suspicious message.
    """
    score = 0
    matched_flags = []
    conditional_matches = []

    for category, data in RED_FLAGS.items():
        if category == "job_conditional":
            continue  # handled after the main loop
        weight = data["weight"]
        for pattern, explanation in data["patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                score += weight
                matched_flags.append((category, weight, explanation))

    # Now handle the conditional category
    for pattern, explanation in RED_FLAGS["job_conditional"]["patterns"]:
        if re.search(pattern, text, re.IGNORECASE):
            conditional_matches.append((pattern, explanation))

    if conditional_matches and matched_flags:
        # Something else already looked suspicious - let part-time-job add weight
        weight = RED_FLAGS["job_conditional"]["weight"]
        for _, explanation in conditional_matches:
            score += weight
            matched_flags.append(("job_conditional", weight, explanation))
    # If conditional_matches exist but matched_flags is empty, we deliberately
    # do nothing - a bare "part-time job" message with nothing else suspicious
    # should not be flagged at all.

    return score, matched_flags


def risk_level(score):
    """
    Turns a weighted score into a human label + a rough percentage.

    Cutoffs are chosen against realistic combos, not raw match counts:
      - 0            -> Looks safe
      - 1-2          -> Some caution (e.g. one urgency word alone)
      - 3-5          -> Some caution, upper end (e.g. one link + one
                         urgency word - not yet a fake-authority/money combo)
      - 6+           -> High risk (this requires at least one weight-3
                         match, i.e. fake_authority or money_request
                         actually showed up - not just noise words)
    """
    if score == 0:
        return "Looks safe", 0
    elif score <= 5:
        # scale 1-5 across roughly 10-40%
        pct = min(10 + (score - 1) * 7, 40)
        return "Some caution advised", pct
    else:
        # 6+ always means at least one fake_authority/money_request hit
        pct = min(50 + (score - 6) * 5, 95)
        return "High risk - likely a scam", pct


def explain_flags(matched_flags):
    """
    Takes the matched_flags list from score_message() and returns
    a readable explanation block, grouped so higher-weight (more
    dangerous) categories are listed first.
    """
    if not matched_flags:
        return "No red flags detected."

    # sort by weight descending so the most dangerous reasons show first
    sorted_flags = sorted(matched_flags, key=lambda f: -f[1])

    lines = []
    for category, weight, explanation in sorted_flags:
        label = category.replace("_", " ").title()
        severity = "high" if weight >= 3 else ("medium" if weight == 2 else "low")
        lines.append(f"- [{label} - {severity} severity] {explanation}")
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
        "explanation": "This mirrors the real Parul University 'fake senior' pattern - an unfamiliar name posing as a senior, using a casual tone and a Google Form to lower suspicion. Note: this scanner scores it as safe (0 red flags) because there's no urgency, money, or authority keyword - the danger is entirely a fabricated identity, which keyword matching cannot detect. This is exactly why Aegis Features 5 and 6 (Ask Faculty verification, Fake Senior Identity Badge) exist alongside this scanner: identity-based social engineering needs a different kind of check than message text does.",
    },
    {
        "text": "Placement Cell: Part-time job openings at the campus library for the semester, Rs 3000/month, apply at the admin office by Friday.",
        "is_scam": False,
        "explanation": "Real part-time job postings from a known office, with a plausible pay rate and no upfront fee, are not suspicious just because they mention 'part-time job'.",
    },
    {
        "text": "Dear Customer, your courier is held at customs due to unpaid duty of Rs 350. Pay immediately via the link below or your parcel will be returned: bit.ly/customs-duty-pay",
        "is_scam": True,
        "explanation": "Fake courier/customs fee scam: small believable amount, false urgency, shortened link, and a fabricated customs process most students have no way to verify quickly.",
    },
    {
        "text": "Your Amazon order 'Wireless Earbuds' has been shipped and is out for delivery today. Track it here: amazon.in/track",
        "is_scam": False,
        "explanation": "Plausible delivery update from a real domain, no payment or urgency demand, nothing to click that requests credentials.",
    },
    {
        "text": "You have WON Rs 25,00,000 in the KBC Lucky Draw 2026! To claim your prize, share your bank account number, IFSC code and pay a refundable processing fee of Rs 4,999.",
        "is_scam": True,
        "explanation": "Classic lottery scam: you can't win a contest you never entered, and legitimate prizes never require you to pay money or share full bank details to receive them.",
    },
    {
        "text": "Hi, this is your semester result notification. Your GPA has been updated on the ERP portal. Login with your student ID to view your grade card.",
        "is_scam": False,
        "explanation": "Routine academic notification pointing to the existing official ERP portal, no external link, OTP, or payment involved.",
    },
    {
        "text": "URGENT: Suspicious login detected on your account from Russia. If this wasn't you, verify your identity now by sharing the OTP sent to your phone or your account will be permanently locked.",
        "is_scam": True,
        "explanation": "OTP-theft scam disguised as a security alert - real security teams never ask you to read an OTP back to them, and the 'permanently locked' threat is designed to stop you from thinking it through.",
    },
    {
        "text": "Reminder from hostel warden: Mess fee payment deadline is the 5th of next month. Pay via the hostel office counter or the official college fee portal.",
        "is_scam": False,
        "explanation": "Realistic recurring campus deadline tied to a known, official payment channel - no external link or unusual payment method requested.",
    },
    {
        "text": "Hi, I'm someone you matched with online. I really feel a connection with you. I'm stuck abroad and need Rs 20,000 urgently for a medical emergency, can you help me, I'll pay you back once I'm home.",
        "is_scam": True,
        "explanation": "Romance scam pattern: emotional urgency from someone you've never met in person, combined with an unexpected direct money request - a near-universal red flag regardless of the story attached.",
    },
    {
        "text": "Hey, are we still meeting at the library at 5pm to study for the DSA test?",
        "is_scam": False,
        "explanation": "Ordinary personal message between classmates with no request for money, credentials, or action outside the conversation.",
    },
    {
        "text": "Internship Offer: Data Science Internship, Rs 15,000/month stipend, remote, immediate start. Pay Rs 2,000 refundable security deposit for your laptop/kit to confirm your seat.",
        "is_scam": True,
        "explanation": "Fake internship scam: legitimate internships never require an upfront 'refundable deposit' before you've even had an interview - this pattern almost always ends with the scammer disappearing after payment.",
    },
    {
        "text": "You've been shortlisted for the Google Summer of Code info session. Details and the official application link are on the GSoC website - check your registered email for the session time.",
        "is_scam": False,
        "explanation": "Plausible, points to the actual official program website rather than a shortened or unfamiliar link, no fee or urgency involved.",
    },
    {
        "text": "This is your telecom provider. Your SIM card will be deactivated tonight due to KYC non-compliance. Press 9 now or share the OTP sent to you to keep your number active.",
        "is_scam": True,
        "explanation": "SIM swap / OTP theft scam: telecom providers do not deactivate numbers same-day over a call, and no provider ever needs you to share an OTP to 'keep a number active'.",
    },
    {
        "text": "Class representative here: tomorrow's Data Structures lecture is moved to Room 204 due to a clash, same time. Let others in the group know.",
        "is_scam": False,
        "explanation": "Routine peer-to-peer academic coordination message with nothing requested beyond passing on information.",
    },
    {
        "text": "Congratulations, your college fee refund of Rs 8,400 has been approved. To receive it, open this link and complete the UPI collect request within the next hour: forms.gle/feerefund2026",
        "is_scam": True,
        "explanation": "Fee refund scam: approving a 'collect request' actually sends money OUT of your account, not in - a common trick disguised as receiving a refund, combined with a short deadline to prevent you checking with the accounts office.",
    },
    {
        "text": "Accounts Office Notice: Fee refunds for cancelled electives will be processed directly to the bank account on your admission form within 15 working days, no action needed from students.",
        "is_scam": False,
        "explanation": "States a real refund process that requires zero action from the student and no link or payment request - genuine refunds don't need you to click anything.",
    },
    {
        "text": "Hi, this is Rohit, TA for your Machine Learning course. Can you send me your enrollment number and date of birth so I can update the attendance sheet before Friday?",
        "is_scam": True,
        "explanation": "Identity-fishing message: this scanner would score it as safe since there's no urgency, money, or link keyword, but a stranger requesting ID details 'for attendance' outside official channels is a classic pretext for identity theft. Like the Divya example, this shows why sender verification (Feature 5/6) matters alongside keyword scanning.",
    },
    {
        "text": "Attendance correction requests must be submitted in person at the department office with your ID card, per university policy. No online form is used for this process.",
        "is_scam": False,
        "explanation": "Describes a real, established in-person process and explicitly states no online form exists for it, which itself helps a student recognize any future online 'attendance form' as suspicious.",
    },
    {
        "text": "Your electricity bill of Rs 2,340 is overdue and power will be disconnected in 3 hours. Pay now via UPI to avoid disconnection: pay-electricity-bill.tk",
        "is_scam": True,
        "explanation": "Fake utility bill scam: extremely short false deadline, an unusual/unofficial-looking domain, and pressure designed to make you pay before you can check your actual account with the utility provider.",
    },
    {
        "text": "Your electricity bill for this month is Rs 1,890, due by the 10th. View and pay via the official state electricity board website or app.",
        "is_scam": False,
        "explanation": "Normal monthly bill notice with a realistic due date and a reference to the genuine official payment channel, no artificial urgency or unfamiliar link.",
    },
    {
        "text": "Dear Student, we noticed unusual activity and your scholarship disbursement is on hold. Verify your bank details and Aadhaar number here to release your funds within 24 hours: tinyurl.com/scholarship-verify",
        "is_scam": True,
        "explanation": "Scholarship phishing scam: combines a false urgency deadline, a shortened link, and a request for sensitive banking and ID details - genuine scholarship offices never ask for Aadhaar numbers through unsolicited links.",
    },
]


# How many questions to draw from QUIZ_BANK per quiz run. QUIZ_BANK
# currently holds 30 questions; each run randomly samples this many,
# with no repeats within that run, so no two runs look identical.
QUIZ_SAMPLE_SIZE = 10


def run_quiz():
    """
    Picks a random sample of QUIZ_SAMPLE_SIZE questions from QUIZ_BANK
    (no repeats within a run), shuffles their order, then loops through
    them asking the user to guess scam or safe, tracking score, and
    revealing the explanation either way.

    If QUIZ_BANK ever has fewer items than QUIZ_SAMPLE_SIZE, this falls
    back to using the whole bank instead of crashing.
    """
    correct_count = 0
    sample_size = min(QUIZ_SAMPLE_SIZE, len(QUIZ_BANK))
    quiz_set = random.sample(QUIZ_BANK, sample_size)

    print("\n=== SCAM AWARENESS QUIZ ===")
    loading_animation("Loading questions")
    print(f"{sample_size} messages, randomly picked from a bank of {len(QUIZ_BANK)}. For each one, decide: Scam or Safe?\n")

    for i, item in enumerate(quiz_set, start=1):
        print(f"--- Message {i}/{sample_size} ---")
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

    print(f"=== Final score: {correct_count}/{sample_size} ===\n")


# ============================================================
# STEP 4: MAIN MENU (glue code)
# ============================================================

def main():
    print("=" * 52)
    print("                Scam Awareness Trainer")
    print("        Aegis Feature 1:  Message & Risk Scanner    ".replace(" ", "_"))
    print("=" * 52)

    while True:
        print("\n1. Analyze a message")
        print("2. Take the awareness quiz")
        print("3. Exit")
        choice = input("\nChoose an option (1-3): ").strip()

        if choice == "1":
            text = input("\nPaste the message to analyze:\n> ")
            print()
            loading_animation("Analyzing message")
            score, matched_flags = score_message(text)
            level, pct = risk_level(score)

            print(f"\nWeighted risk score: {score}")
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