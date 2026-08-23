"""
MORROW 1.0 - Scam Awareness Trainer
=====================================
Core idea: don't just flag scam messages, TEACH the user why it's a scam.
Two modes: (1) Analyze a message the user pastes in
           (2) Quiz mode - show real scam examples, test if user can spot them

Build order (do these in sequence, don't jump around):
  1. RED_FLAGS dictionary + score_message() function   <- the brain
  2. explain_flags() function                          <- turns matches into plain English
  3. QUIZ_BANK list + run_quiz() function               <- the demo-friendly part
  4. main() with a simple menu tying it together        <- glue
  5. (stretch) swap input() loop for a basic Tkinter window
"""

import re



# STEP 1: THE RED FLAG RULEBOOK


# TODO: expand each list. Use the real scam SMS examples from your
# research here. Every pattern should be something you can point to
# in a REAL scam text you found.
#
# Structure: category_name -> list of (regex_pattern, plain_english_explanation)
# Keeping the explanation attached to the pattern now saves you pain later
# in step 2 - you won't have to map patterns to explanations separately.

RED_FLAGS = {
    "urgency": [
        (r"\bimmediately\b", "creates false time pressure so you act without thinking"),
        (r"\bwithin 24 hours\b", "creates false time pressure so you act without thinking"),
        (r"\bblocked\b", "threatens loss of access to scare you into reacting fast"),
        # TODO: add more from your Goa/Maharashtra examples - "account suspended", "last warning" etc
    ],
    "fake_authority": [
        (r"\bCBI\b", "impersonates a law enforcement agency - real agencies don't contact you like this"),
        (r"\bcustoms\b", "impersonates a government body to sound official"),
        (r"\bdigital arrest\b", "this is NOT a real legal term - no such thing exists in Indian law"),
        # TODO: add "RBI", "income tax", bank names, police, etc
    ],
    "money_request": [
        (r"\bOTP\b", "no legitimate service ever asks you to share an OTP"),
        (r"\bUPI PIN\b", "you never need to enter your PIN to RECEIVE money, only to send it"),
        (r"\brefund\b", "refund scams trick you into approving a payment, not receiving one"),
        # TODO: add "KYC", "verify account", "collect request" etc
    ],
    "suspicious_link": [
        (r"bit\.ly", "shortened links hide the real destination website"),
        (r"tinyurl", "shortened links hide the real destination website"),
        # TODO: add other common shortened-link services or fake domain patterns
    ],
}
# REMINDER: keep this rulebook DATA, not logic. Judges will like seeing
# how easy it is to add new scam patterns without touching the code.



# STEP 2: THE SCORING + EXPLAINING ENGINE


def score_message(text):
    """
    Takes a message string, returns:
      - total_score (int)
      - matched_flags (list of (category, explanation) tuples)
    TODO: write the loop.
    Pseudocode:
        set score = 0
        set matched_flags = []
        for each category, pattern_list in RED_FLAGS.items():
            for each (pattern, explanation) in pattern_list:
                if pattern found in text (use re.search, IGNORECASE):
                    score += 1
                    matched_flags.append((category, explanation))
        return score, matched_flags
    """
    pass  # <-- replace with real code


def risk_level(score):
    """
    Turns a raw score into a human label.
    TODO: decide your own thresholds once you test against real examples.
    Suggested starting point:
        0        -> "Looks safe"
        1-2      -> "Some caution advised"
        3+       -> "High risk - likely a scam"
    """
    pass  # <-- replace with real code


def explain_flags(matched_flags):
    """
    Takes the matched_flags list from score_message() and prints/returns
    a readable explanation block.
    TODO:
        if matched_flags is empty:
            return "No red flags detected."
        else:
            build a bullet-point string, one line per flag, e.g.:
            "- [urgency] creates false time pressure so you act without thinking"
    THIS FUNCTION IS YOUR PITCH'S CORE VALUE. Spend real time making
    the wording clear and non-technical - a judge or a first-time
    internet user should understand it instantly.
    """
    pass  # <-- replace with real code



# STEP 3: QUIZ MODE (this is your demo showpiece)

# TODO: fill this with REAL scam message examples from your research
# (Goa/Maharashtra news articles, government advisories) alongside
# made-up safe messages for contrast. Aim for 8-10 pairs minimum.
#
# Structure: each entry is a dict so it's easy to loop over and extend.

QUIZ_BANK = [
    {
        "text": "PASTE A REAL OR REALISTIC SCAM MESSAGE HERE",
        "is_scam": True,
        "explanation": "why this one is a scam, in plain words",
    },
    {
        "text": "PASTE A REALISTIC SAFE / LEGITIMATE MESSAGE HERE",
        "is_scam": False,
        "explanation": "why this one is safe",
    },
    # TODO: add 8-10 more entries. Mix scam and safe roughly 50/50.
]


def run_quiz():
    """
    Loops through QUIZ_BANK, shows each message, asks user to guess
    scam or safe, tracks score, reveals the explanation either way.
    Pseudocode:
        set correct_count = 0
        for each item in QUIZ_BANK:
            print the message text
            ask: "Scam or Safe? (s/f): "
            compare user answer to item["is_scam"]
            if correct: correct_count += 1, print "Correct!"
            else: print "Not quite."
            always print item["explanation"] right after - this is
            the teaching moment, don't skip it even on a correct answer
        print final score out of len(QUIZ_BANK)
    """
    pass  # <-- replace with real code



# STEP 4: MAIN MENU (glue code, do this LAST)


def main():
    """
    TODO:
        print a simple welcome banner
        loop:
            show menu:
              1. Analyze a message
              2. Take the awareness quiz
              3. Exit
            get user choice
            if 1: get input(text), call score_message(), risk_level(),
                  explain_flags(), print results nicely
            if 2: call run_quiz()
            if 3: break
    Keep this simple. A clean CLI menu demos perfectly fine -
    do NOT let this turn into your time sink. Save polish time
    for the rule list and quiz bank content, not the menu UI.
    """
     # <-- replace with real code


if __name__ == "__main__":
    main()


# STRETCH GOALS (only if steps 1-4 are solid and tested)

# - Swap input()/print() loop for a basic Tkinter window
#   (Label, Text box, Button, another Label for results)
# - Track quiz score across a session and show a "your awareness
#   level" summary at the end
# - Add a language toggle for a couple of Hindi/Marathi example
#   messages - good for the pitch's "future roadmap" slide even
#   if only partially working
#
# DO NOT START THESE until run_quiz() and score_message() both
# work reliably on your test messages. A working simple demo beats
# a broken ambitious one.``