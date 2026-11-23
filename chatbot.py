"""
chatbot.py - Helper chatbot and Scam Simulator for ScamShield AI.

1. Helper bot  : keyword matching -> predefined safety answers (English/Hindi/Hinglish).
                 If the user pastes a suspicious message, link or number, it runs the
                 real detector and explains the result.
2. Simulator   : a pretend scammer talks to the user in a short scripted chat. The user
                 picks replies; at the end they get an awareness score and are shown
                 exactly where they would have been fooled.
"""
import random
import re

import detector

# ======================================================================
# 1. HELPER BOT
# ======================================================================
HELPLINE = "Cyber fraud helpline: 1930  |  Online report: cybercrime.gov.in"

INTENTS = [
    {
        "name": "greeting",
        "keywords": ["hello", "hi", "hey", "namaste", "namaskar", "hii", "नमस्ते"],
        "reply": "Namaste! Main ScamShield Helper hun. Aap koi SMS, link ya number paste karein, "
                 "ya scam ke baare mein kuch bhi poochein.",
    },
    {
        "name": "otp",
        "keywords": ["otp", "ओटीपी", "pin", "cvv", "password"],
        "reply": "OTP, PIN, CVV aur password KISI ko na batayein - bank, police ya company ke naam par bhi nahi. "
                 "Jo ye maangta hai wo fraud hai. Agar galti se share ho gaya, turant bank ko call karke "
                 "card/account block karwayein aur 1930 par report karein.",
    },
    {
        "name": "kyc",
        "keywords": ["kyc", "केवाईसी", "account band", "account block", "khata band", "pan update"],
        "reply": "Bank KYC ke liye SMS link ya call par details nahi maangta. 'Account band ho jayega' wala "
                 "message fraud hota hai. KYC ke liye bank ki official app ya branch jayein.",
    },
    {
        "name": "digital_arrest",
        "keywords": ["digital arrest", "arrest", "cbi", "police call", "giraftar", "narcotics", "गिरफ्तार"],
        "reply": "'Digital arrest' jaisi koi cheez kanoon mein nahi hoti. Police/CBI video call par arrest nahi karti "
                 "aur paisa nahi maangti. Call kaat dein, kisi ko paisa na dein, aur 1930 par report karein.",
    },
    {
        "name": "report",
        "keywords": ["report", "helpline", "1930", "complaint", "shikayat", "cyber crime", "cybercrime", "kahan"],
        "reply": "Fraud report karne ke liye:\n1) 1930 par call karein (jitni jaldi, utna better)\n"
                 "2) cybercrime.gov.in par online complaint karein\n3) Apne bank ko turant call karein.\n"
                 "Is app mein bhi 'Report' option se scam number add kar sakte hain.",
    },
    {
        "name": "lost_money",
        "keywords": ["paisa chala gaya", "money lost", "fraud ho gaya", "scam ho gaya", "paise kat gaye", "lost money", "thaga gaya"],
        "reply": "Ghabrayein nahi, turant ye karein:\n1) 1930 par call karein (pehle 'golden hour' mein paisa rok sakte hain)\n"
                 "2) Bank ko call karke account/card block karwayein\n3) cybercrime.gov.in par complaint karein\n"
                 "4) Saare screenshots/SMS sambhal kar rakhein.",
    },
    {
        "name": "upi",
        "keywords": ["upi", "qr", "paytm", "phonepe", "gpay", "google pay", "collect request"],
        "reply": "UPI mein paisa lene ke liye PIN daalne ki zaroorat NAHI hoti. Agar koi 'paisa bhej raha hun, "
                 "PIN daalo' ya QR scan karwa kar paisa lene ko kahe, to wo fraud hai. Unknown collect request decline karein.",
    },
    {
        "name": "fake_job",
        "keywords": ["job", "part time", "work from home", "task", "like and earn", "naukri", "kamai"],
        "reply": "Aasan kaam, bade paise, 'like karo aur kamao' - ye fake job scam ke sign hain. Asli job mein kaam "
                 "se pehle fee ya deposit nahi maanga jata. Telegram/WhatsApp job offers se savdhan rahein.",
    },
    {
        "name": "lottery",
        "keywords": ["lottery", "lucky draw", "prize", "inaam", "kbc", "jeet", "लॉटरी"],
        "reply": "Jo contest aapne bhara hi nahi, usme aap jeet nahi sakte. 'Prize ke liye fee bhejo' kehne wala "
                 "pakka fraud hai. Message delete karein aur number block karein.",
    },
    {
        "name": "link",
        "keywords": ["link", "url", "website", "click", "phishing", "लिंक"],
        "reply": "Unknown link par click na karein. Link mein bank/company ka naam ho par domain alag ho "
                 "(jaise sbi-kyc.xyz) to wo nakli hai. Aap link yahan paste karein, main check kar dunga.",
    },
    {
        "name": "courier",
        "keywords": ["courier", "parcel", "customs", "delivery", "fedex", "dhl"],
        "reply": "Parcel/customs ke naam par fee maangne wale messages aksar fraud hote hain. Courier company ki "
                 "official app/website par tracking khud check karein, diye gaye link par nahi.",
    },
    {
        "name": "electricity",
        "keywords": ["bijli", "electricity", "power cut", "bill pay", "बिजली"],
        "reply": "'Aaj raat bijli kat jayegi' wale messages fraud hote hain. Bijli bill sirf apne board ki "
                 "official app/website se check aur pay karein.",
    },
    {
        "name": "tips",
        "keywords": ["tips", "safe kaise", "bachao", "bachne", "protect", "safety", "kaise bachein", "suraksha"],
        "reply": "Scam se bachne ke 5 rules:\n1) OTP/PIN/CVV kisi ko nahi\n2) Unknown link par click nahi\n"
                 "3) Jaldbaazi = shak (ruk kar sochein)\n4) Remote apps (AnyDesk) install nahi karein\n"
                 "5) Shak ho to 1930 ya bank ko call karein.",
    },
    {
        "name": "how_to_use",
        "keywords": ["kaise use", "how to use", "kaise kaam", "kya karta", "what can you do", "help", "madad"],
        "reply": "Aap kar sakte hain:\n- SMS ya message paste karke risk check\n- Link ya phone number check\n"
                 "- Scam Simulator se practice\n- Naya scam number report\nBas message yahan paste kar dein!",
    },
    {
        "name": "thanks",
        "keywords": ["thanks", "thank you", "shukriya", "dhanyavaad", "धन्यवाद"],
        "reply": "Aapka swagat hai! Savdhan rahein aur doston-parivar ko bhi bataiye.",
    },
    {
        "name": "bye",
        "keywords": ["bye", "goodbye", "alvida", "ok bye"],
        "reply": "Alvida! Safe rahiye. 🛡️",
    },
]

SUGGESTIONS = ["OTP kya hai?", "Digital arrest kya hota hai?", "Fraud report kahan karein?", "Scam se kaise bachein?"]

FALLBACK = ("Mujhe ye samajh nahi aaya. Aap koi SMS/link/number paste kar sakte hain, "
            "ya in mein se kuch poochein.")


def _kw_hit(text, kw):
    if all(ord(c) < 128 for c in kw):
        return re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text) is not None
    return kw in text


def _match_intent(text):
    best, best_score = None, 0
    for intent in INTENTS:
        score = sum(len(kw.split()) for kw in intent["keywords"] if _kw_hit(text, kw))
        if score > best_score:
            best, best_score = intent, score
    return best


def _analysis_reply(msg):
    r = detector.combined_check(msg)
    lines = [f"Risk: {r['level']} ({r['score']}/100)"]
    if r["scam_type"] and r["scam_type"] != "No clear scam pattern":
        lines.append(f"Scam type: {r['scam_type']}")
    top = [t["matched"] for t in r["sms"]["triggers"] if t["points"] > 0][:4]
    if top:
        lines.append("Shak wale signs: " + ", ".join(top))
    if r["urls"]:
        lines.append(f"Links mile: {len(r['urls'])} (sabse risky link ka score {max(u['score'] for u in r['urls'])})")
    if r["phones"]:
        lines.append(f"Numbers mile: {len(r['phones'])}")
    lines.append(r["advice"][0] if r["advice"] else "")
    return {"reply": "\n".join(x for x in lines if x), "analysis": r, "suggestions": []}


def chat_reply(message):
    msg = (message or "").strip()
    if not msg:
        return {"reply": "Kuch likhiye ya koi message paste kijiye.", "suggestions": SUGGESTIONS}
    t = " ".join(msg.lower().split())

    has_url = bool(detector.extract_urls(msg))
    has_phone = bool(detector.extract_phones(msg, detector.extract_urls(msg)))
    intent = _match_intent(t)

    # a pasted link/number, or a long pasted message, is analysed with the real detector
    if has_url or has_phone or (len(t) > 80 and intent is None):
        return _analysis_reply(msg)
    if len(t) > 80 and intent is not None and detector.check_sms(msg)["score"] > 30:
        return _analysis_reply(msg)

    if intent:
        return {"reply": intent["reply"], "intent": intent["name"],
                "suggestions": [] if intent["name"] in ("thanks", "bye") else ["Fraud report kahan karein?", "Scam se kaise bachein?"]}
    return {"reply": FALLBACK, "suggestions": SUGGESTIONS}


# ======================================================================
# 2. SCAM SIMULATOR
# ======================================================================
def _step(scammer, safe, mid, bad):
    """Each step: what the 'scammer' says + 3 reply options (safe / risky / very risky)."""
    return {
        "scammer": scammer,
        "options": [
            {"id": 0, "text": safe[0], "risk": 0, "feedback": safe[1]},
            {"id": 1, "text": mid[0], "risk": 1, "feedback": mid[1]},
            {"id": 2, "text": bad[0], "risk": 2, "feedback": bad[1]},
        ],
    }


SCENARIOS = {
    "kyc": {
        "title": "Fake Bank Call (KYC)",
        "intro": "Aapke phone par ek unknown number se call aata hai...",
        "steps": [
            _step("Hello sir, main SBI head office se bol raha hun. Aapka KYC expire ho gaya hai, aaj hi account band ho jayega!",
                  ("Main khud branch/app se check karunga.", "Sahi! Asli bank dabaav nahi daalta, aur aap khud verify kar sakte hain."),
                  ("Arre nahi, ab kya karna padega?", "Ghabrahat scammer ka hathiyaar hai. Pehle ruk kar verify karna chahiye."),
                  ("Ji bataiye, main kya karun?", "Aapne scammer par bharosa kar liya. 'Account band' ka darr dikhana unka pehla step hai.")),
            _step("Aapke phone par link bheja hai, usse KYC form bhar dijiye, bas 2 minute lagenge.",
                  ("Link par click nahi karunga.", "Bahut badhiya! Unknown link phishing ka sabse bada raasta hai."),
                  ("Link dekhta hun, par details nahi dunga.", "Link kholna bhi risky hai, fake site device ko nuksan pahucha sakti hai."),
                  ("Theek hai, form bhar deta hun.", "Fake form se aapki personal aur bank details chori ho sakti hain.")),
            _step("Form mein OTP aayega, wo mujhe bata dijiye, warna account band ho jayega.",
                  ("OTP kisi ko nahi deta. Call kaat raha hun.", "Perfect! OTP dena matlab paisa seedha scammer ko dena."),
                  ("Pehle apna employee ID batao.", "Baat jaari rakhna risky hai, scammer fake ID bhi bata dega. Seedha call kaat dein."),
                  ("OTP 482913 hai.", "OTP share karte hi account se paisa nikal sakta hai!")),
            _step("Verification ke liye ab apne card ka CVV aur PIN bhi bata dijiye.",
                  ("Call kaat kar bank ko khud call karunga aur 1930 par report karunga.", "Bilkul sahi! Shak hote hi report karna best step hai."),
                  ("CVV de deta hun, PIN nahi.", "CVV bhi online payment ke liye kaafi hai. Kuch bhi share na karein."),
                  ("CVV aur PIN dono bata deta hun.", "Ab scammer ke paas aapke card ka poora control hai.")),
        ],
    },
    "digital_arrest": {
        "title": "Digital Arrest Scare",
        "intro": "Aapke paas ek video call aati hai, screen par police jaisi vardi dikhti hai...",
        "steps": [
            _step("Main CBI officer bol raha hun. Aapke naam se ek parcel mila hai jisme drugs hain. Aapke khilaf arrest warrant hai!",
                  ("Ye galat lagta hai. Main call kaat raha hun.", "Sahi! Police aise video call par kabhi arrest nahi karti."),
                  ("Par maine to kuch bheja hi nahi, please samjhiye.", "Safai dene se scammer ko aur control milta hai. Call kaat dena behtar hai."),
                  ("Sir please mujhe bachaiye, main kya karun?", "Darr hi scammer ka asli hathiyaar hai.")),
            _step("Video call par bane rahiye aur kisi ko mat batayein, warna case kharaab ho jayega.",
                  ("Main apne parivar ko abhi batata hun.", "Zaroor! 'Kisi ko mat batana' scam ka sabse bada red flag hai."),
                  ("Theek hai, par thodi der ke liye hi.", "Kisi ko na batana aapko akela karne ki chaal hai."),
                  ("Ji sir, main kisi ko nahi bataunga.", "Isolate karna scammer ka main step hai, isse bachein.")),
            _step("Case band karne ke liye abhi 'verification amount' is account mein transfer kijiye.",
                  ("Police paisa nahi maangti. Main 1930 par call kar raha hun.", "Bilkul sahi! Koi bhi sarkari agency paisa transfer nahi karwati."),
                  ("Kitna amount hai, pehle bataiye.", "Amount puchna matlab aap maanne lage. Seedha mana karein."),
                  ("Theek hai, abhi transfer karta hun.", "Paisa transfer karte hi wo wapas aana bahut mushkil ho jata hai.")),
        ],
    },
    "job": {
        "title": "Fake Part-time Job",
        "intro": "Aapko WhatsApp par ek unknown number se message aata hai...",
        "steps": [
            _step("Hi! Part-time job hai, ghar baithe roz ₹5000 kamaiye, sirf YouTube videos like karne hain.",
                  ("Unknown offer hai, main ignore karta hun.", "Sahi! Aasan kaam + bade paise = scam ka sign."),
                  ("Thoda aur batao, kaise kaam hai?", "Baat badhane se scammer aapko apne jaal mein kheenchta hai."),
                  ("Haan mujhe interest hai!", "Lalach scam ka pehla darwaza hai.")),
            _step("Ye lo, 3 tasks complete kiye, ₹150 mil gaye! Ab Telegram group join karo, bade tasks wahin milenge.",
                  ("Chhote payment se bharosa nahi karunga. Block kar raha hun.", "Badhiya! Chhota payment sirf bharosa jeetne ki chaal hoti hai."),
                  ("Group join karke dekhta hun.", "Telegram group mein aur bhi scammers aur fake 'members' hote hain."),
                  ("Join kar liya!", "Ab aap unke jaal mein aage badh gaye hain.")),
            _step("Bade task ke liye ₹10,000 deposit karna hoga, wapas double milega.",
                  ("Deposit maangna scam hai. Number block aur report.", "Bilkul sahi! Asli job mein kaam se pehle paisa nahi maanga jata."),
                  ("Sirf ₹1000 deke dekhta hun.", "Chhoti rakam bhi jaati hai, aur phir aur maange jaate hain."),
                  ("Ye lo ₹10,000 bhej diye.", "Paisa gaya, aur wapas aane ki umeed bahut kam hai.")),
        ],
    },
    "lottery": {
        "title": "Lucky Draw Prize",
        "intro": "Aapke phone par ek SMS aata hai: 'Congratulations! You have won...'",
        "steps": [
            _step("Badhai ho! Aapne ₹25 lakh ki lottery jeeti hai. Prize claim karne ke liye reply kijiye.",
                  ("Maine koi lottery bhari hi nahi. Delete.", "Sahi! Jo contest bhara hi nahi, usme aap jeet nahi sakte."),
                  ("Kaun si lottery? Zara details bhejiye.", "Jawab dene se scammer ko pata chal jata hai ki aapka number active hai."),
                  ("Wow! Main claim karna chahta hun.", "Lalach ne aapko jaal mein phasa diya.")),
            _step("Claim ke liye aapko ₹4,999 processing fee deni hogi, fir poora prize aapke account mein.",
                  ("Asli prize mein fee nahi lagti. Block kar raha hun.", "Perfect! Fee maangna fraud ka pakka sign hai."),
                  ("Fee kam ho sakti hai kya?", "Mol-bhaav karne se aap maanne lage. Seedha mana karein."),
                  ("Theek hai, ₹4,999 bhej deta hun.", "Fee dene ke baad aur-aur fees maangi jayengi.")),
        ],
    },
}


def list_scenarios():
    return [{"id": k, "title": v["title"], "intro": v["intro"], "steps": len(v["steps"])}
            for k, v in SCENARIOS.items()]


def _public_step(scenario_id, index):
    """Step data for the client - without risk or feedback, with options shuffled."""
    scenario = SCENARIOS[scenario_id]
    step = scenario["steps"][index]
    options = [{"id": o["id"], "text": o["text"]} for o in step["options"]]
    random.shuffle(options)
    return {"scenario": scenario_id, "title": scenario["title"], "step": index,
            "total": len(scenario["steps"]), "scammer": step["scammer"], "options": options}


def start_scenario(scenario_id):
    if scenario_id not in SCENARIOS:
        return None
    return {"intro": SCENARIOS[scenario_id]["intro"], "first": _public_step(scenario_id, 0)}


def answer_step(scenario_id, step_index, option_id, answers):
    """
    answers: list of option ids chosen on the previous steps (client keeps it).
    Returns feedback for this answer and either the next step or the final summary.
    """
    if scenario_id not in SCENARIOS:
        return None
    steps = SCENARIOS[scenario_id]["steps"]
    if not isinstance(step_index, int) or not 0 <= step_index < len(steps):
        return None
    chosen = next((o for o in steps[step_index]["options"] if o["id"] == option_id), None)
    if chosen is None:
        return None

    all_answers = list(answers or [])[:step_index] + [option_id]
    out = {"risk": chosen["risk"], "feedback": chosen["feedback"]}
    if step_index + 1 < len(steps):
        out["finished"] = False
        out["next"] = _public_step(scenario_id, step_index + 1)
    else:
        out["finished"] = True
        out["summary"] = summarize(scenario_id, all_answers)
    return out


def summarize(scenario_id, answers):
    steps = SCENARIOS[scenario_id]["steps"]
    penalty, fell = 0, []
    for i, step in enumerate(steps):
        oid = answers[i] if i < len(answers) else 2
        chosen = next(o for o in step["options"] if o["id"] == oid)
        safe = next(o for o in step["options"] if o["risk"] == 0)
        penalty += chosen["risk"]
        if chosen["risk"] > 0:
            fell.append({
                "step": i + 1,
                "scammer_said": step["scammer"],
                "you_chose": chosen["text"],
                "problem": chosen["feedback"],
                "better_reply": safe["text"],
            })
    score = round(100 * (1 - penalty / (2 * len(steps))))
    if score >= 85:
        verdict = "Scam-proof! Aap scammers ke jaal mein nahi phanse."
    elif score >= 50:
        verdict = "Thoda savdhan rahiye. Kuch jagah aap phans sakte the."
    else:
        verdict = "Khatra! Asli zindagi mein aap fraud ka shikar ho sakte the. Tips dobara padhein."
    return {"score": score, "verdict": verdict, "fell_for": fell,
            "tip": "Yaad rakhein: OTP/PIN kisi ko nahi, jaldbaazi = shak, aur shak ho to 1930 par call karein."}
