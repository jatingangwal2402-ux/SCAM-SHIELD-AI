"""
rules.py - All rule data for ScamShield AI.

Everything the detector knows lives here (phrases, points, advice), so the
detection logic in detector.py stays small and the rules are easy to extend.
Phrases are lower-case. Devanagari (Hindi) phrases are matched as-is.
Each phrase is a tuple: (phrase, points).
"""

# ----------------------------------------------------------------------
# Risk levels
# ----------------------------------------------------------------------
LOW_MAX = 30       # 0-30   -> Low
MEDIUM_MAX = 60    # 31-60  -> Medium, 61+ -> High


def level_for(score):
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"


# ----------------------------------------------------------------------
# Scam types (English + Hindi + Hinglish phrases)
# ----------------------------------------------------------------------
SCAM_TYPES = {
    "digital_arrest": {
        "name": "Digital Arrest / Fake Police Scam",
        "explain": "Scammers pretend to be police, CBI or customs officers and "
                   "threaten arrest to scare you into paying money. No real "
                   "agency arrests anyone over a video call.",
        "advice": [
            "Call turant kaat do. Asli police 'digital arrest' nahi karti.",
            "Kisi ko paisa ya bank details mat do.",
            "Cyber crime helpline 1930 par call karein ya cybercrime.gov.in par report karein.",
        ],
        "phrases": [
            ("digital arrest", 35), ("arrest warrant", 30), ("money laundering", 25),
            ("narcotics", 20), ("drugs found", 30), ("cbi officer", 25),
            ("customs officer", 20), ("cyber crime branch", 20), ("mumbai police", 15),
            ("stay on the call", 20), ("do not disconnect", 25),
            ("video call par rahiye", 25), ("video call par rahein", 25),
            ("kisi ko na batayein", 25), ("kisi ko mat batana", 25),
            ("aap par case darj", 25), ("giraftar", 25), ("giraftari", 25),
            ("गिरफ्तार", 25), ("गिरफ्तारी वारंट", 30), ("सीबीआई", 20),
        ],
    },
    "kyc_block": {
        "name": "KYC / Bank Account Block Scam",
        "explain": "The message claims your bank account, card or wallet will be "
                   "blocked unless you 'update KYC' through a link or by sharing details. "
                   "Banks never ask for KYC through SMS links.",
        "advice": [
            "Link par click mat karein.",
            "Apne bank ki official app ya branch se direct check karein.",
            "Card number, PIN ya OTP kisi ko na dein.",
        ],
        "phrases": [
            ("kyc update", 25), ("update kyc", 25), ("kyc expire", 30), ("kyc", 15),
            ("account will be blocked", 30), ("account blocked", 25),
            ("account suspended", 25), ("account band ho jayega", 30),
            ("account band", 25), ("khata band", 25), ("bank account freeze", 25),
            ("card blocked", 25), ("pan card update", 25), ("pan not linked", 25),
            ("aadhaar link", 15), ("update immediately", 15),
            ("केवाईसी", 25), ("खाता बंद", 30), ("आपका खाता बंद", 30), ("खाता ब्लॉक", 30),
        ],
    },
    "otp_request": {
        "name": "OTP / PIN / Password Theft",
        "explain": "Someone is asking for an OTP, PIN, CVV or password. Anyone who "
                   "asks for these is a fraudster - even if they say they are from the bank.",
        "advice": [
            "OTP, PIN, CVV ya password KISI ko na batayein.",
            "Bank kabhi call ya SMS par ye cheezein nahi maangta.",
            "Agar galti se share ho gaya to turant bank ko call karke card/account block karwayein.",
        ],
        "phrases": [
            ("share otp", 35), ("send otp", 35), ("otp bhejo", 35), ("otp batao", 35),
            ("otp share karein", 35), ("otp", 15), ("cvv", 30), ("atm pin", 30),
            ("upi pin", 35), ("pin number", 25), ("card number", 20), ("password bhejo", 30),
            ("ओटीपी बताएं", 35), ("ओटीपी", 25),
        ],
    },
    "lottery": {
        "name": "Lottery / Prize Scam",
        "explain": "You are told you have won a lottery, lucky draw or prize, but "
                   "must pay a 'fee' or share details first. You cannot win a contest you never entered.",
        "advice": [
            "Koi fee ya tax dene ki zaroorat nahi, ye fraud hai.",
            "Message delete karein aur number block karein.",
        ],
        "phrases": [
            ("you have won", 30), ("claim your prize", 30), ("lucky draw", 25),
            ("lottery", 25), ("prize money", 25), ("lottery lagi", 30), ("jeet liya", 25),
            ("inaam", 20), ("kbc", 20), ("processing fee", 25), ("congratulations", 10),
            ("लॉटरी", 25), ("इनाम", 20),
        ],
    },
    "fake_job": {
        "name": "Fake Job / Part-time Task Scam",
        "explain": "Easy 'work from home' or 'like and earn' offers that first give "
                   "tiny payouts, then ask you to deposit bigger and bigger amounts.",
        "advice": [
            "Asli job mein kaam shuru karne se pehle paisa nahi maanga jata.",
            "Telegram/WhatsApp par aaye job offers par bharosa na karein.",
        ],
        "phrases": [
            ("part time job", 30), ("part-time job", 30), ("work from home", 20),
            ("daily earning", 25), ("earn per day", 25), ("per day income", 25),
            ("like and earn", 30), ("youtube like", 25), ("telegram group", 20),
            ("task complete", 20), ("registration fee", 25), ("ghar baithe kamao", 30),
            ("ghar baithe", 20), ("job offer", 10),
            ("पार्ट टाइम जॉब", 30), ("रोज़ कमाएं", 25),
        ],
    },
    "courier": {
        "name": "Fake Courier / Customs Scam",
        "explain": "A parcel is said to be held, undelivered or contains something "
                   "illegal, and you are asked to pay a fee or click a link.",
        "advice": [
            "Courier company ki official app/website par tracking khud check karein.",
            "Kisi unknown link par delivery fee na dein.",
        ],
        "phrases": [
            ("pay customs fee", 30), ("package held", 25), ("parcel rok liya", 30),
            ("delivery failed", 20), ("address incomplete", 25), ("reschedule delivery", 20),
            ("customs", 20), ("courier", 15), ("parcel", 15), ("fedex", 15), ("dhl", 10),
            ("पार्सल", 15),
        ],
    },
    "electricity": {
        "name": "Electricity Bill Disconnection Scam",
        "explain": "The message says your power will be cut tonight unless you pay or "
                   "call a number. Electricity boards do not threaten like this.",
        "advice": [
            "Bijli bill apne board ki official app/website par check karein.",
            "Message mein diye number par call na karein.",
        ],
        "phrases": [
            ("power will be disconnected", 35), ("electricity will be disconnected", 35),
            ("bijli kat", 30), ("connection kat", 30), ("bill not updated", 25),
            ("tonight 9:30", 30), ("electricity bill", 20), ("bijli bill", 20),
            ("electricity connection", 20), ("disconnect", 20),
            ("बिजली कनेक्शन", 25), ("बिजली का बिल", 20), ("कट जाएगा", 30),
        ],
    },
    "refund_reward": {
        "name": "Fake Refund / Loan / Reward Scam",
        "explain": "Offers of tax refunds, instant loans or reward points that 'expire "
                   "today' are used to push you onto a fake link or app.",
        "advice": [
            "Refund/reward sirf official website ya app se claim karein.",
            "Unknown loan app install na karein.",
        ],
        "phrases": [
            ("income tax refund", 30), ("tax refund", 30), ("instant loan", 25),
            ("pre-approved loan", 20), ("loan approved", 20), ("no documents", 15),
            ("reward points", 25), ("points expire", 30), ("cashback", 15),
            ("redeem", 15), ("refund", 10),
        ],
    },
}

# ----------------------------------------------------------------------
# Generic pressure / trap patterns (not tied to one scam type)
# ----------------------------------------------------------------------
GENERIC_PATTERNS = [
    # (phrase, points, label, reason)
    ("urgent", 10, "Urgency", "Scammers create hurry so you do not think."),
    ("immediately", 10, "Urgency", "Scammers create hurry so you do not think."),
    ("turant", 15, "Urgency", "'Turant' jaise shabd jaldbaazi karwane ke liye use hote hain."),
    ("jaldi", 10, "Urgency", "Jaldbaazi scam ka common tarika hai."),
    ("तुरंत", 15, "Urgency", "'तुरंत' jaise shabd jaldbaazi karwane ke liye use hote hain."),
    ("within 24 hours", 15, "Urgency", "Fake deadline diya gaya hai."),
    ("last chance", 15, "Urgency", "Fake deadline diya gaya hai."),
    ("expire today", 20, "Urgency", "Fake deadline diya gaya hai."),
    ("click here", 15, "Click bait", "Message aapko link par click karwana chahta hai."),
    ("click the link", 15, "Click bait", "Message aapko link par click karwana chahta hai."),
    ("link par click", 20, "Click bait", "Message aapko link par click karwana chahta hai."),
    ("लिंक पर क्लिक", 20, "Click bait", "Message aapko link par click karwana chahta hai."),
    ("download app", 15, "App install", "Unknown app install karwana ek common trick hai."),
    ("anydesk", 35, "Remote access app", "AnyDesk se scammer aapka phone/computer control kar sakta hai."),
    ("teamviewer", 35, "Remote access app", "TeamViewer se scammer aapka device control kar sakta hai."),
    ("quicksupport", 35, "Remote access app", "Remote access app se scammer aapka device control kar sakta hai."),
]

# Patterns that mean the SMS is a genuine "do not share OTP" warning
OTP_SAFETY_NOTICE = (
    r"(do not|don't|dont|never)\s+(share|disclose|give)|share\s+na\s+kar|"
    r"na\s+bata|mat\s+(batao|bhejo|share)|किसी को न|साझा न"
)

# ----------------------------------------------------------------------
# URL rules
# ----------------------------------------------------------------------
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "ow.ly", "buff.ly", "rebrand.ly", "bl.ink",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "work", "loan", "live", "icu", "buzz", "cfd", "sbs",
    "vip", "cyou", "rest", "fit", "gq", "tk", "ml", "ga", "cf", "monster",
}

SUSPICIOUS_URL_WORDS = [
    "login", "verify", "update", "kyc", "secure", "bonus", "reward", "claim",
    "free", "gift", "prize", "refund", "suspend", "unlock", "confirm",
]

# brand keyword -> official registered domains
OFFICIAL_DOMAINS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbicard.com", "sbi.bank.in"],
    "hdfc": ["hdfcbank.com", "hdfc.com", "hdfcbank.net"],
    "icici": ["icicibank.com", "icicidirect.com"],
    "axis": ["axisbank.com"],
    "pnb": ["pnbindia.in", "netpnb.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
    "aadhaar": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in"],
    "indiapost": ["indiapost.gov.in"],
    "npci": ["npci.org.in"],
    "google": ["google.com", "google.co.in"],
    "microsoft": ["microsoft.com"],
    "netflix": ["netflix.com"],
}

TWO_PART_SUFFIXES = {
    "co.in", "gov.in", "org.in", "nic.in", "ac.in", "net.in", "res.in",
    "co.uk", "com.au", "bank.in",
}

# ----------------------------------------------------------------------
# Phone rules
# ----------------------------------------------------------------------
# Report count -> points
PHONE_REPORT_POINTS = [(10, 75), (3, 55), (1, 35)]  # (min reports, points)

# ----------------------------------------------------------------------
# Level-based advice (shown with every result)
# ----------------------------------------------------------------------
LEVEL_ADVICE = {
    "Low": [
        "Koi bada khatra nahi dikha, phir bhi link/number par sochkar hi action lein.",
        "Agar kuch galat lage to bank ki official app se verify karein.",
    ],
    "Medium": [
        "Savdhan rahein: is message mein kuch shak wale signs hain.",
        "Link par click ya call back karne se pehle official website/app se confirm karein.",
        "OTP, PIN ya card details share na karein.",
    ],
    "High": [
        "Ye bahut sambhavna hai ki fraud hai. Click, reply ya call na karein.",
        "Number block karein aur message delete karein.",
        "Agar paisa chala gaya hai to turant 1930 par call karein.",
    ],
}
