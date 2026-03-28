import re


def extract_urls_from_text(text):
    pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    urls = re.findall(pattern, text)
    cleaned = []

    for u in urls:
        u = u.strip(".,!?)]}>'\"")
        if u.startswith("www."):
            u = "http://" + u
        cleaned.append(u)

    return cleaned