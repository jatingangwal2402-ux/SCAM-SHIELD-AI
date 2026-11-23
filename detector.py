"""
detector.py - Core detection logic for ScamShield AI (rule-based).

Public functions
----------------
check_sms(text)       -> risk result for an SMS / message
check_url(url)        -> risk result for a URL
check_phone(number)   -> risk result for a phone number
combined_check(text)  -> extracts URLs + phones from a message and checks all three
family_alert(result)  -> ready-made WhatsApp warning message
"""
import re
import ipaddress
from urllib.parse import urlparse

import database
import rules

# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
URL_REGEX = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:[a-z0-9\-]+\.)+(?:com|in|net|org|xyz|top|click|online|site|live|icu|vip|cc|info|link|"
    r"me|ly|gl|app|shop|work|buzz|cfd|sbs|biz|co|ai|io)\b(?:/[^\s<>\"']*)?"
)

INDIAN_MOBILE_REGEX = re.compile(r"(?<![\d.])(?:\+?91[\s\-]?|0)?[6-9]\d{4}[\s\-]?\d{5}(?!\d)")
INTL_REGEX = re.compile(r"(?<![\d.])\+(?!91)\d{1,3}[\s\-]?\d{6,12}(?!\d)")


def _is_ascii(s):
    return all(ord(c) < 128 for c in s)


def _contains(text, phrase):
    """Whole-word match for ASCII phrases, plain match for Hindi (Devanagari)."""
    if _is_ascii(phrase):
        pattern = r"(?<![a-z0-9])" + re.escape(phrase) + r"(?![a-z0-9])"
        return re.search(pattern, text) is not None
    return phrase in text


def _clean_url_tail(u):
    return u.rstrip(".,;:!?)]}'\"")


def extract_urls(text):
    found = []
    for m in URL_REGEX.finditer(text):
        u = _clean_url_tail(m.group(0))
        if u and u.lower() not in [x.lower() for x in found]:
            found.append(u)
    return found


def normalize_phone(raw):
    """Return (digits_only_10, is_international). Indian numbers become 10 digits."""
    raw = raw.strip()
    is_intl = raw.startswith("+") and not raw.startswith("+91")
    digits = re.sub(r"\D", "", raw)
    if not is_intl:
        if len(digits) == 12 and digits.startswith("91"):
            digits = digits[2:]
        elif len(digits) == 11 and digits.startswith("0"):
            digits = digits[1:]
    return digits, is_intl


def extract_phones(text, urls=()):
    """Find phone numbers in text (ignoring digits that are part of a URL)."""
    cleaned = text
    for u in urls:
        cleaned = cleaned.replace(u, " ")
    found = []
    for rx in (INDIAN_MOBILE_REGEX, INTL_REGEX):
        for m in rx.finditer(cleaned):
            raw = m.group(0).strip()
            digits, intl = normalize_phone(raw)
            key = ("+" + digits) if intl else digits
            if key not in [k for k, _ in found]:
                found.append((key, raw))
    return [raw for _, raw in found]


def _result(kind, text, score, level, triggers, advice, **extra):
    out = {
        "kind": kind,
        "input": text,
        "score": score,
        "level": level,
        "triggers": triggers,
        "advice": advice,
    }
    out.update(extra)
    return out


# ----------------------------------------------------------------------
# SMS checker
# ----------------------------------------------------------------------
def check_sms(text):
    t = " ".join(text.lower().split())
    triggers = []
    type_scores = {}
    otp_notice = re.search(rules.OTP_SAFETY_NOTICE, t) is not None

    for key, info in rules.SCAM_TYPES.items():
        if key == "otp_request" and otp_notice:
            continue  # genuine "do not share OTP" warning, not a request
        matched = [(p, pts) for p, pts in info["phrases"] if _contains(t, p)]
        # drop a phrase if a longer matched phrase already contains it (avoid double counting)
        matched = [
            (p, pts) for p, pts in matched
            if not any(p != q and p in q for q, _ in matched)
        ]
        for p, pts in matched:
            triggers.append({
                "matched": p,
                "category": info["name"],
                "points": pts,
                "why": f"'{p}' aam taur par '{info['name']}' mein use hota hai.",
            })
        if matched:
            type_scores[key] = sum(pts for _, pts in matched)

    seen = set()
    for phrase, pts, label, reason in rules.GENERIC_PATTERNS:
        if _contains(t, phrase) and (label, phrase) not in seen:
            seen.add((label, phrase))
            triggers.append({"matched": phrase, "category": label, "points": pts, "why": reason})

    if re.search(r"\.apk\b", t):
        triggers.append({
            "matched": ".apk", "category": "App install", "points": 30,
            "why": "APK file link se app install karna phone hack karwa sakta hai.",
        })

    if otp_notice and "otp" in t:
        triggers.append({
            "matched": "OTP safety notice", "category": "Info", "points": 0,
            "why": "Message mein 'OTP share na karein' jaisi chetavani hai, jo asli bank SMS mein hoti hai.",
        })

    score = min(100, sum(x["points"] for x in triggers))
    level = rules.level_for(score)

    scam_key, scam_name = None, "No clear scam pattern"
    if type_scores:
        best = max(type_scores, key=type_scores.get)
        if type_scores[best] >= 20:
            scam_key, scam_name = best, rules.SCAM_TYPES[best]["name"]

    advice = list(rules.SCAM_TYPES[scam_key]["advice"]) if scam_key else []
    advice += rules.LEVEL_ADVICE[level]

    risky_triggers = [x for x in triggers if x["points"] > 0]
    if risky_triggers and scam_key:
        explanation = rules.SCAM_TYPES[scam_key]["explain"]
    elif risky_triggers:
        explanation = "Kuch shak wale shabd mile, lekin kisi ek scam type se match nahi hua."
    else:
        explanation = "Koi jaana-pehchana scam pattern nahi mila."

    return _result(
        "sms", text, score, level, triggers, advice,
        scam_type=scam_name, scam_type_key=scam_key, explanation=explanation,
    )


# ----------------------------------------------------------------------
# URL checker
# ----------------------------------------------------------------------
def _registered_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in rules.TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_url(url):
    raw = url.strip()
    parse_target = raw if re.match(r"(?i)^https?://", raw) else "http://" + raw
    had_scheme = bool(re.match(r"(?i)^https?://", raw))
    parsed = urlparse(parse_target)
    host = (parsed.hostname or "").lower()
    triggers = []

    def add(matched, category, pts, why):
        triggers.append({"matched": matched, "category": category, "points": pts, "why": why})

    if not host:
        return _result("url", url, 0, "Low", [], ["Valid URL daalein, jaise https://example.com"],
                       host="", official=False, explanation="URL samajh nahi aaya.")

    reg = _registered_domain(host)
    official = any(
        host == d or host.endswith("." + d)
        for domains in rules.OFFICIAL_DOMAINS.values() for d in domains
    )

    if _is_ip(host):
        add(host, "IP address", 30, "Asli companies IP address ki jagah domain naam use karti hain.")
    if "@" in parsed.netloc:
        add("@", "Hidden destination", 25, "'@' ke baad wala hissa asli destination hota hai, ye ek trick hai.")
    if had_scheme and parsed.scheme == "http":
        add("http://", "No HTTPS", 15, "Link secure (HTTPS) nahi hai.")
    if host in rules.URL_SHORTENERS:
        add(host, "Short link", 20, "Short link asli destination chhupa deta hai.")
    tld = host.rsplit(".", 1)[-1]
    if tld in rules.SUSPICIOUS_TLDS and not official:
        add("." + tld, "Suspicious domain ending", 20, f".{tld} domains scam sites mein bahut common hain.")
    if host.count("-") >= 2:
        add("hyphens", "Many hyphens", 10, "Bahut saare '-' wale domain aksar nakli hote hain.")
    if host.count(".") >= 4:
        add("subdomains", "Too many subdomains", 10, "Bahut saare subdomain asli site ki nakal ho sakte hain.")
    if "xn--" in host:
        add("xn--", "Look-alike characters", 25, "Punycode se asli site jaisa dikhne wala nakli domain banta hai.")

    # brand look-alike (e.g. sbi-kyc-update.xyz)
    flat_host = host.replace("-", "").replace(".", "")
    if not official:
        for brand in rules.OFFICIAL_DOMAINS:
            if brand in flat_host:
                add(brand, "Brand look-alike", 35,
                    f"Domain mein '{brand}' naam hai, lekin ye '{brand}' ka official domain nahi hai.")
                break

    full = (host + parsed.path + (("?" + parsed.query) if parsed.query else "")).lower()
    words = [w for w in rules.SUSPICIOUS_URL_WORDS if w in full]
    if words:
        add(", ".join(words[:3]), "Suspicious words", min(20, 10 * len(words)),
            "URL mein aise shabd hain jo login/verify karwane ke liye use hote hain.")
    if len(raw) > 75:
        add("long URL", "Very long URL", 5, "Bahut lambe URL mein aksar asli destination chhupa hota hai.")

    score = min(100, sum(x["points"] for x in triggers))
    if official and not any(x["category"] in ("Hidden destination", "No HTTPS") for x in triggers):
        score = min(score, 10)
        triggers.append({"matched": reg, "category": "Official domain", "points": 0,
                         "why": f"{reg} ek jaana-pehchana official domain hai."})
    level = rules.level_for(score)
    advice = list(rules.LEVEL_ADVICE[level])
    if level != "Low":
        advice.insert(0, "Is link ko khol kar koi details (login, OTP, card) na daalein.")

    if triggers and score > rules.LOW_MAX:
        explanation = "Is link mein kai shak wale signs hain: " + ", ".join(
            sorted({x["category"] for x in triggers if x["points"] > 0})) + "."
    elif official:
        explanation = "Link official domain ka lagta hai."
    else:
        explanation = "Koi bada suspicious sign nahi mila, phir bhi savdhan rahein."

    return _result("url", url, score, level, triggers, advice,
                   host=host, official=official, explanation=explanation)


# ----------------------------------------------------------------------
# Phone checker
# ----------------------------------------------------------------------
def check_phone(number):
    digits, is_intl = normalize_phone(number)
    triggers = []

    def add(matched, category, pts, why):
        triggers.append({"matched": matched, "category": category, "points": pts, "why": why})

    key = ("+" + digits) if is_intl else digits
    record = None

    if is_intl:
        add(number.strip(), "International number", 25,
            "Videsh ke number se bank/KYC/police ke naam par call aana shak wali baat hai.")
    else:
        valid_mobile = len(digits) == 10 and digits[0] in "6789"
        if digits.startswith("140"):
            add("140", "Telemarketing series", 20, "140 se shuru hone wale number telemarketing ke hote hain.")
        elif not valid_mobile:
            add(number.strip(), "Invalid format", 15, "Ye 10 digit ka valid Indian mobile number nahi lagta.")
        if len(set(digits)) <= 2 and len(digits) >= 8:
            add(digits, "Repeated digits", 10, "Aise 'fancy' ya repeated digit number kabhi-kabhi spam ke liye use hote hain.")

    record = database.lookup_number(key)
    if record:
        pts = 0
        for min_reports, p in rules.PHONE_REPORT_POINTS:
            if record["reports"] >= min_reports:
                pts = p
                break
        add(key, "Reported number", pts,
            f"Is number ke khilaf {record['reports']} report(s) hain ({record['scam_type']}).")

    score = min(100, sum(x["points"] for x in triggers))
    level = rules.level_for(score)
    advice = list(rules.LEVEL_ADVICE[level])
    if record:
        advice.insert(0, "Is number se aaye call/SMS ka jawab na dein aur number block karein.")
    else:
        advice.append("Is number ki koi report hamare database mein nahi hai, par iska matlab 'safe' nahi hai.")

    explanation = (
        f"Ye number {record['reports']} baar report ho chuka hai." if record
        else "Is number ke khilaf hamare local database mein koi report nahi mili."
    )
    return _result("phone", number, score, level, triggers, advice,
                   normalized=key, reports=record["reports"] if record else 0,
                   scam_type=record["scam_type"] if record else None, explanation=explanation)


# ----------------------------------------------------------------------
# Combined checker (SMS + URLs + phones found inside it)
# ----------------------------------------------------------------------
def combined_check(text):
    sms = check_sms(text)
    urls = extract_urls(text)
    phones = extract_phones(text, urls)

    url_results = [check_url(u) for u in urls]
    phone_results = [check_phone(p) for p in phones]

    max_url = max([r["score"] for r in url_results], default=0)
    max_phone = max([r["score"] for r in phone_results], default=0)

    bonus = 0
    if urls and sms["triggers"]:
        bonus += 5  # a message that both sounds scammy and carries a link
    final = min(100, sms["score"] + round(0.6 * max_url) + round(0.6 * max_phone) + bonus)
    level = rules.level_for(final)

    advice = []
    for a in sms["advice"] + [a for r in url_results for a in r["advice"]]:
        if a not in advice and a not in rules.LEVEL_ADVICE["Low"] + rules.LEVEL_ADVICE["Medium"] + rules.LEVEL_ADVICE["High"]:
            advice.append(a)
    for a in rules.LEVEL_ADVICE[level]:
        if a not in advice:
            advice.append(a)

    result = {
        "kind": "combined",
        "input": text,
        "score": final,
        "level": level,
        "scam_type": sms["scam_type"],
        "scam_type_key": sms["scam_type_key"],
        "explanation": sms["explanation"],
        "sms": sms,
        "urls": url_results,
        "phones": phone_results,
        "advice": advice,
        "breakdown": {
            "message": sms["score"],
            "links": round(0.6 * max_url),
            "numbers": round(0.6 * max_phone),
            "bonus": bonus,
        },
    }
    result["family_alert"] = family_alert(result)
    return result


# ----------------------------------------------------------------------
# Family alert (WhatsApp ready message)
# ----------------------------------------------------------------------
def family_alert(result):
    if result["level"] == "Low":
        return ""
    scam = result.get("scam_type")
    scam_line = f"Ye '{scam}' jaisa lag raha hai.\n" if scam and scam != "No clear scam pattern" else ""
    snippet = " ".join(result["input"].split())
    if len(snippet) > 120:
        snippet = snippet[:117] + "..."
    return (
        "⚠️ Scam alert! Mujhe ek message/call aaya jo fraud lag raha hai "
        f"(risk: {result['level']}).\n"
        f"{scam_line}"
        f"Message: \"{snippet}\"\n\n"
        "Is par click mat karna, OTP/PIN/card details kisi ko mat dena, aur is number ko block karna. "
        "Paisa chala jaye to turant 1930 par call karo.\n"
        "- ScamShield AI se check kiya gaya"
    )
