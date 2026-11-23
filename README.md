# ScamShield AI

Call, SMS & URL Fraud Detector with Helper Chatbot.
Rule-based (koi paid API ya ML model nahi). Python Flask + SQLite + HTML/CSS/JS.

## Run kaise karein

Python 3.9+ chahiye.

```bash
cd scamshield
python -m venv venv

# Windows
venv\Scripts\activate
# Mac / Linux
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

Phir browser mein kholein: **http://127.0.0.1:5000**
(Mobile par test karne ke liye, same Wi-Fi par phone mein `http://<laptop-ka-IP>:5000` kholein.)

Database (`scamshield.db`) pehli baar run par apne aap ban jata hai, sample data ke saath.

## Tests chalana

```bash
python -m unittest discover -s tests -v
```

31 test cases hain (SMS, URL, phone, combined, chatbot, simulator). Report ke Testing chapter mein inhi ko use karein.

## Features

| Feature | Kahan hai |
|---|---|
| SMS checker (English, Hindi, Hinglish phrases) | `detector.check_sms`, rules `rules.py` |
| URL checker (shortener, HTTPS, look-alike domain, IP, suspicious words) | `detector.check_url` |
| Phone checker (SQLite reports + format rules) | `detector.check_phone`, `database.py` |
| Scam Story Detector (8 scam types) | `rules.SCAM_TYPES` |
| Combined Check (message se link + number khud nikalna) | `detector.combined_check` |
| Result explanation + safety advice | har result mein "Message ki jaanch" aur "Ab kya karein" |
| Helper chatbot (keyword matching) | `chatbot.chat_reply` |
| Scam Simulator (4 scenarios, score, galtiyan) | `chatbot.py` (SCENARIOS) |
| Family Alert (WhatsApp message) | `detector.family_alert` |
| Report button (community database) | `/api/report`, `database.report_number` |
| History (SQLite) | `/api/history`, `database.py` |
| Mobile-friendly UI, dark mode | `templates/index.html`, `static/` |

## Risk score

Har pattern ke points jodte hain (max 100): **0-30 Low, 31-60 Medium, 61+ High**.
Combined check mein: message ke points + 0.6 x sabse risky link + 0.6 x sabse risky number + 5 (agar message scammy hai aur link bhi hai).

## Folder structure

```
scamshield/
  app.py            Flask routes (API + page)
  detector.py       SMS / URL / phone / combined checking
  chatbot.py        helper bot + scam simulator
  database.py       SQLite tables aur queries
  rules.py          saare scam phrases, points, advice
  templates/index.html
  static/style.css, static/app.js
  tests/            unit tests
```

## Naye rules jodna

`rules.py` kholein. `SCAM_TYPES` mein kisi type ke `phrases` mein `("naya phrase", points)` add karein, ya naya type banayein. Code badalne ki zaroorat nahi.

## API

| Route | Method | Body |
|---|---|---|
| `/api/check/combined` | POST | `{"text": "..."}` |
| `/api/check/sms` | POST | `{"text": "..."}` |
| `/api/check/url` | POST | `{"url": "..."}` |
| `/api/check/phone` | POST | `{"number": "..."}` |
| `/api/report` | POST | `{"number": "...", "scam_type": "..."}` |
| `/api/chat` | POST | `{"message": "..."}` |
| `/api/simulator/scenarios` | GET | |
| `/api/simulator/start` | POST | `{"scenario": "kyc"}` |
| `/api/simulator/answer` | POST | `{"scenario", "step", "option", "answers"}` |
| `/api/history` | GET / DELETE | |

## Dhyan dein

- Ye **rule-based** hai, isliye 100% sahi nahi ho sakta. Naye tarah ke scams pakadne ke liye rules update karne padenge.
- Database ke 7 sample phone numbers (`9000000001` se `9000000007`) **dummy** hain, kisi asli vyakti ke nahi.
- Fraud ho jaye to turant **1930** par call karein ya cybercrime.gov.in par report karein.
