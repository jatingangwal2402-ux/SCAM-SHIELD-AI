"""
app.py - Flask server for ScamShield AI.

Run:  python app.py      then open http://127.0.0.1:5000
"""
from flask import Flask, jsonify, render_template, request

import chatbot
import database
import detector

# Static files live in public/static so Vercel can serve them from its CDN (same URL: /static/...)
app = Flask(__name__, static_folder="public/static", static_url_path="/static")
database.init_db()


def _text_from_request(field):
    data = request.get_json(silent=True) or {}
    value = (data.get(field) or "").strip()
    return data, value


def _error(msg, code=400):
    return jsonify({"error": msg}), code


@app.route("/")
def home():
    return render_template("index.html")


# ---------------------------------------------------------------- checkers
@app.route("/api/check/sms", methods=["POST"])
def api_sms():
    _, text = _text_from_request("text")
    if not text:
        return _error("Message khali hai. Kuch likhein ya paste karein.")
    if len(text) > 2000:
        return _error("Message bahut lamba hai (max 2000 characters).")
    result = detector.check_sms(text)
    database.add_history("sms", text, result["score"], result["level"], result["scam_type"])
    return jsonify(result)


@app.route("/api/check/url", methods=["POST"])
def api_url():
    _, url = _text_from_request("url")
    if not url:
        return _error("URL khali hai.")
    if len(url) > 2000:
        return _error("URL bahut lamba hai.")
    result = detector.check_url(url)
    database.add_history("url", url, result["score"], result["level"])
    return jsonify(result)


@app.route("/api/check/phone", methods=["POST"])
def api_phone():
    _, number = _text_from_request("number")
    if not number:
        return _error("Number khali hai.")
    if len(number) > 30:
        return _error("Number bahut lamba hai.")
    result = detector.check_phone(number)
    database.add_history("phone", number, result["score"], result["level"], result.get("scam_type"))
    return jsonify(result)


@app.route("/api/check/combined", methods=["POST"])
def api_combined():
    _, text = _text_from_request("text")
    if not text:
        return _error("Message khali hai. Kuch likhein ya paste karein.")
    if len(text) > 2000:
        return _error("Message bahut lamba hai (max 2000 characters).")
    result = detector.combined_check(text)
    database.add_history("combined", text, result["score"], result["level"], result["scam_type"])
    return jsonify(result)


# ---------------------------------------------------------------- report
@app.route("/api/report", methods=["POST"])
def api_report():
    data, number = _text_from_request("number")
    if not number:
        return _error("Number khali hai.")
    digits, is_intl = detector.normalize_phone(number)
    if not is_intl and not (len(digits) == 10 and digits[0] in "6789"):
        return _error("Valid 10 digit Indian mobile number daalein.")
    key = ("+" + digits) if is_intl else digits
    scam_type = (data.get("scam_type") or "Unknown").strip()[:60]
    total = database.report_number(key, scam_type)
    return jsonify({"ok": True, "number": key, "total_reports": total,
                    "message": "Report darj ho gayi. Dhanyavaad, isse dusron ki madad hogi."})


# ---------------------------------------------------------------- chatbot
@app.route("/api/chat", methods=["POST"])
def api_chat():
    _, message = _text_from_request("message")
    if len(message) > 2000:
        return _error("Message bahut lamba hai (max 2000 characters).")
    return jsonify(chatbot.chat_reply(message))


# ---------------------------------------------------------------- scam simulator
@app.route("/api/simulator/scenarios", methods=["GET"])
def api_sim_list():
    return jsonify(chatbot.list_scenarios())


@app.route("/api/simulator/start", methods=["POST"])
def api_sim_start():
    data = request.get_json(silent=True) or {}
    out = chatbot.start_scenario(data.get("scenario"))
    if out is None:
        return _error("Scenario nahi mila.", 404)
    return jsonify(out)


@app.route("/api/simulator/answer", methods=["POST"])
def api_sim_answer():
    data = request.get_json(silent=True) or {}
    out = chatbot.answer_step(data.get("scenario"), data.get("step"), data.get("option"), data.get("answers"))
    if out is None:
        return _error("Galat scenario, step ya option.")
    return jsonify(out)


# ---------------------------------------------------------------- history
@app.route("/api/history", methods=["GET"])
def api_history():
    return jsonify(database.get_history())


@app.route("/api/history", methods=["DELETE"])
def api_history_clear():
    database.clear_history()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
