function showPopup(result) {
    const popup = document.getElementById("popup");
    const content = document.getElementById("popupContent");

    popup.style.display = "flex";

    let color = "green";
    if (result.status === "Fraud") color = "red";
    else if (result.status === "Suspicious") color = "orange";
    else if (result.status === "Error") color = "crimson";

    content.innerHTML = `
        <h2 style="color:${color}; margin-bottom:10px;">${result.status}</h2>
        <p><b>Risk Score:</b> ${result.risk}%</p>
        <ul>
            ${result.reasons.map(r => `<li>${r}</li>`).join("")}
        </ul>
        <button onclick="closePopup()">Close</button>
    `;
}

function closePopup() {
    document.getElementById("popup").style.display = "none";
}

window.addEventListener("click", function(event) {
    const popup = document.getElementById("popup");
    if (event.target === popup) {
        closePopup();
    }
});

function checkSMS() {
    const text = document.getElementById("smsText").value.trim();

    if (!text) {
        showPopup({
            status: "Error",
            risk: 0,
            reasons: ["Please enter SMS text before checking."]
        });
        return;
    }

    fetch("/check_sms", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ text: text })
    })
    .then(res => res.json())
    .then(data => showPopup(data))
    .catch(err => {
        showPopup({
            status: "Error",
            risk: 0,
            reasons: ["SMS request failed: " + err]
        });
    });
}

function checkURL() {
    const url = document.getElementById("urlInput").value.trim();

    if (!url) {
        showPopup({
            status: "Error",
            risk: 0,
            reasons: ["Please enter a URL before checking."]
        });
        return;
    }

    fetch("/check_url", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: url })
    })
    .then(res => res.json())
    .then(data => showPopup(data))
    .catch(err => {
        showPopup({
            status: "Error",
            risk: 0,
            reasons: ["URL request failed: " + err]
        });
    });
}

function checkImage() {
    const fileInput = document.getElementById("imageInput");

    if (!fileInput || !fileInput.files.length) {
        showPopup({
            status: "Error",
            risk: 0,
            reasons: ["Please upload an image first."]
        });
        return;
    }

    const formData = new FormData();
    formData.append("image", fileInput.files[0]);

    fetch("/check_image", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => showPopup(data))
    .catch(err => {
        showPopup({
            status: "Error",
            risk: 0,
            reasons: ["Image request failed: " + err]
        });
    });
}

function checkQR() {
    const fileInput = document.getElementById("qrInput");

    if (!fileInput || !fileInput.files.length) {
        showPopup({
            status: "Error",
            risk: 0,
            reasons: ["Please upload a QR image first."]
        });
        return;
    }

    const formData = new FormData();
    formData.append("image", fileInput.files[0]);

    fetch("/check_qr", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => showPopup(data))
    .catch(err => {
        showPopup({
            status: "Error",
            risk: 0,
            reasons: ["QR request failed: " + err]
        });
    });
}