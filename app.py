import os
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

from detectors.sms_detector import analyze_sms
from detectors.url_detector import analyze_url
from detectors.image_detector import analyze_image
from detectors.qr_detector import analyze_qr

app = Flask(__name__)

# Upload folder setup
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# =========================
# PAGE ROUTES
# =========================
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/sms")
def sms_page():
    return render_template("sms.html")


@app.route("/url")
def url_page():
    return render_template("url.html")


@app.route("/image")
def image_page():
    return render_template("image.html")


@app.route("/qr")
def qr_page():
    return render_template("qr.html")


# =========================
# API ROUTES
# =========================
@app.route("/check_sms", methods=["POST"])
def check_sms():
    try:
        data = request.get_json()

        if not data or "text" not in data:
            return jsonify({
                "status": "Error",
                "risk": 0,
                "reasons": ["No SMS text provided."]
            })

        text = data["text"].strip()

        if not text:
            return jsonify({
                "status": "Error",
                "risk": 0,
                "reasons": ["SMS text is empty."]
            })

        result = analyze_sms(text)
        return jsonify(result)

    except Exception as e:
        return jsonify({
            "status": "Error",
            "risk": 0,
            "reasons": [f"SMS detection failed: {str(e)}"]
        })


@app.route("/check_url", methods=["POST"])
def check_url():
    try:
        data = request.get_json()

        if not data or "url" not in data:
            return jsonify({
                "status": "Error",
                "risk": 0,
                "reasons": ["No URL provided."]
            })

        url = data["url"].strip()

        if not url:
            return jsonify({
                "status": "Error",
                "risk": 0,
                "reasons": ["URL is empty."]
            })

        result = analyze_url(url)
        return jsonify(result)

    except Exception as e:
        return jsonify({
            "status": "Error",
            "risk": 0,
            "reasons": [f"URL detection failed: {str(e)}"]
        })


@app.route("/check_image", methods=["POST"])
def check_image():
    try:
        if "image" not in request.files:
            return jsonify({
                "status": "Error",
                "risk": 0,
                "reasons": ["No image file uploaded."]
            })

        file = request.files["image"]

        if file.filename == "":
            return jsonify({
                "status": "Error",
                "risk": 0,
                "reasons": ["No image selected."]
            })

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        result = analyze_image(filepath)

        # Optional: remove file after analysis
        try:
            os.remove(filepath)
        except:
            pass

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "status": "Error",
            "risk": 0,
            "reasons": [f"Image detection failed: {str(e)}"]
        })


@app.route("/check_qr", methods=["POST"])
def check_qr():
    try:
        if "image" not in request.files:
            return jsonify({
                "status": "Error",
                "risk": 0,
                "reasons": ["No QR image uploaded."]
            })

        file = request.files["image"]

        if file.filename == "":
            return jsonify({
                "status": "Error",
                "risk": 0,
                "reasons": ["No QR image selected."]
            })

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        result = analyze_qr(filepath)

        # Optional: remove file after analysis
        try:
            os.remove(filepath)
        except:
            pass

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "status": "Error",
            "risk": 0,
            "reasons": [f"QR detection failed: {str(e)}"]
        })


# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    app.run(debug=True)