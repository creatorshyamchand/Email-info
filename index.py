import json
import re
import requests
import smtplib
import socket
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Try importing dnspython (optional for Vercel)
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ---------------- CONFIG ----------------
HIBP_API = "https://haveibeenpwned.com/api/v3/breaches"
DISPOSABLE_DOMAINS_URL = "https://disposable.github.io/disposable-email-domains/domains.json"

# ---------------- HELPER FUNCTIONS ----------------

def validate_format(email):
    """Validate email format"""
    pattern = r'^[\w\.\+\-]+@[\w\-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        username, domain = email.split("@", 1)
        return True, username, domain
    return False, "", ""

def get_mx_records(domain):
    """Get MX records for domain"""
    if not DNS_AVAILABLE:
        return []
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return sorted([str(r.exchange).rstrip('.') for r in records])
    except Exception:
        return []

def check_smtp(email, domain, mx_records):
    """Check SMTP deliverability"""
    if not mx_records:
        return None, "No MX records found"
    try:
        mx_host = mx_records[0]
        with smtplib.SMTP(timeout=10) as smtp:
            smtp.connect(mx_host)
            smtp.helo(socket.gethostname())
            smtp.mail('test@example.com')
            code, msg = smtp.rcpt(email)
            if code == 250:
                return True, "Mailbox exists"
            elif code == 550:
                return False, "Mailbox does not exist"
            else:
                return None, f"Uncertain (code {code})"
    except Exception as e:
        return None, f"SMTP check failed: {str(e)}"

def check_disposable(domain):
    """Check if email is from disposable domain"""
    try:
        resp = requests.get(DISPOSABLE_DOMAINS_URL, timeout=5)
        if resp.status_code == 200:
            domains = resp.json()
            return domain.lower() in domains
    except Exception:
        pass
    return None

def get_domain_info(domain):
    """Get domain WHOIS information"""
    try:
        url = f"https://api.whoisjsonapi.com/v1/{domain}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "registrar": data.get("registrar", {}).get("name", "N/A"),
                "creation_date": data.get("creation_date", "N/A"),
                "country": data.get("registrant", {}).get("country", "N/A"),
            }
    except Exception:
        pass
    return {"registrar": "N/A", "creation_date": "N/A", "country": "N/A"}

def check_breaches(domain):
    """Check if domain appeared in data breaches"""
    try:
        url = f"{HIBP_API}?domain={domain}"
        headers = {"User-Agent": "Nexxon-Hackers-Email-Checker"}
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            names = [b.get("Name", "") for b in data]
            return names, len(names)
    except Exception:
        pass
    return [], 0

def get_email_info(email, do_smtp=True):
    """Main function to get email information"""
    result = {
        "email": email,
        "checked_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "checked_timestamp": int(datetime.utcnow().timestamp())
    }
    
    # 1. Format Validation
    is_valid, username, domain = validate_format(email)
    result["is_valid_format"] = is_valid
    result["username"] = username
    result["domain"] = domain
    
    if not is_valid:
        result["success"] = False
        result["error"] = "Invalid email format"
        return result
    
    result["success"] = True
    
    # 2. MX Records
    mx_records = get_mx_records(domain)
    result["mx_records"] = mx_records
    result["has_mx"] = bool(mx_records)
    
    # 3. SMTP Check
    if do_smtp and DNS_AVAILABLE:
        deliverable, message = check_smtp(email, domain, mx_records)
        result["smtp_deliverable"] = deliverable
        result["smtp_message"] = message
    else:
        result["smtp_deliverable"] = None
        result["smtp_message"] = "SMTP check skipped (DNS unavailable or disabled)"
    
    # 4. Disposable Check
    result["is_disposable"] = check_disposable(domain)
    
    # 5. Domain WHOIS
    whois = get_domain_info(domain)
    result["domain_registrar"] = whois["registrar"]
    result["domain_creation_date"] = whois["creation_date"]
    result["domain_country"] = whois["country"]
    
    # 6. Breach Check
    breaches, breach_count = check_breaches(domain)
    result["breaches"] = breaches[:10]  # Limit to 10 breaches
    result["breach_count"] = breach_count
    
    # Add API Info
    result["api_info"] = {
        "developed_by": "Creator Shyamchand & Ayan",
        "organization": "CEO & Founder Of - Nexxon Hackers",
        "version": "1.0.0"
    }
    
    return result

def batch_lookup(emails, do_smtp=False):
    """Perform batch lookup for multiple emails"""
    results = []
    for email in emails:
        email = email.strip()
        if email:
            info = get_email_info(email, do_smtp)
            results.append(info)
    return results

# ---------------- HTML TEMPLATE ----------------
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Email Information API - Nexxon Hackers</title>
<script src="https://cdn.tailwindcss.com/3.4.16"></script>
<script>tailwind.config={theme:{extend:{colors:{primary:'#f59e0b',secondary:'#d97706'},borderRadius:{'none':'0px','sm':'4px',DEFAULT:'8px','md':'12px','lg':'16px','xl':'20px','2xl':'24px','3xl':'32px','full':'9999px','button':'8px'}}}}</script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/remixicon/4.6.0/remixicon.min.css" rel="stylesheet">
<style>
.loading-spinner {
    border: 2px solid #f3f3f3;
    border-top: 2px solid #f59e0b;
    border-radius: 50%;
    width: 16px;
    height: 16px;
    animation: spin 1s linear infinite;
    display: inline-block;
}
@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}
.json-viewer {
    background: #1e1e1e;
    border-radius: 8px;
    padding: 16px;
    overflow-x: auto;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 13px;
    line-height: 1.5;
}
.json-key { color: #9cdcfe; }
.json-string { color: #ce9178; }
.json-number { color: #b5cea8; }
.json-boolean { color: #569cd6; }
.json-null { color: #569cd6; }
.glow-text {
    text-shadow: 0 0 20px rgba(245, 158, 11, 0.3);
}
</style>
</head>
<body class="bg-gradient-to-br from-amber-50 via-white to-orange-50 min-h-screen">
<main class="pt-8 pb-12 px-4 max-w-4xl mx-auto">
    
    <!-- Header -->
    <header class="text-center py-8">
        <div class="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-primary to-secondary rounded-3xl mb-6 shadow-lg">
            <i class="ri-mail-line text-white ri-3x"></i>
        </div>
        <h1 class="text-4xl font-bold text-gray-900 mb-2 glow-text">Email Information API</h1>
        <p class="text-lg text-gray-600 mb-2">Advanced Email Validation & Intelligence Service</p>
        <p class="text-sm text-gray-500">Format Check • MX Records • SMTP • Disposable • Breaches • WHOIS</p>
    </header>

    <!-- Live Test Section -->
    <section class="mb-8 bg-white rounded-3xl p-8 shadow-xl border border-amber-100">
        <h2 class="text-xl font-bold text-gray-900 mb-6 flex items-center">
            <i class="ri-flask-line text-primary mr-2"></i>
            Live API Test
        </h2>
        <div class="flex flex-col sm:flex-row gap-3 mb-4">
            <input type="email" id="emailInput" placeholder="Enter email address (e.g., test@gmail.com)" 
                   class="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent outline-none">
            <button id="testBtn" class="bg-gradient-to-r from-primary to-secondary text-white px-6 py-3 rounded-lg font-medium hover:shadow-lg transition flex items-center justify-center gap-2">
                <i class="ri-search-line"></i>
                <span>Check Email</span>
            </button>
        </div>
        <div class="flex gap-2 mb-4 flex-wrap">
            <button onclick="document.getElementById('emailInput').value='test@gmail.com'; document.getElementById('testBtn').click()" 
                    class="text-xs bg-amber-50 hover:bg-amber-100 px-3 py-1 rounded-full text-amber-700 transition border border-amber-200">
                Try Gmail
            </button>
            <button onclick="document.getElementById('emailInput').value='user@yahoo.com'; document.getElementById('testBtn').click()" 
                    class="text-xs bg-amber-50 hover:bg-amber-100 px-3 py-1 rounded-full text-amber-700 transition border border-amber-200">
                Try Yahoo
            </button>
            <button onclick="document.getElementById('emailInput').value='test@tempmail.com'; document.getElementById('testBtn').click()" 
                    class="text-xs bg-amber-50 hover:bg-amber-100 px-3 py-1 rounded-full text-amber-700 transition border border-amber-200">
                Try Temp Mail
            </button>
        </div>
        <div class="mb-4">
            <label class="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" id="smtpCheck" class="w-4 h-4 text-primary rounded">
                <span class="text-sm text-gray-600">Enable SMTP check (slower but more accurate)</span>
            </label>
        </div>
        <div id="responseContainer" class="hidden">
            <div class="flex items-center justify-between mb-2">
                <span class="text-sm font-medium text-gray-700">Response:</span>
                <button id="copyBtn" class="text-xs text-primary hover:text-secondary flex items-center gap-1">
                    <i class="ri-file-copy-line"></i> Copy
                </button>
            </div>
            <pre id="responseDisplay" class="json-viewer"></pre>
        </div>
        <div id="loadingIndicator" class="hidden text-center py-8">
            <div class="loading-spinner w-8 h-8"></div>
            <span class="ml-3 text-gray-500">Analyzing email address...</span>
        </div>
        <div id="errorDisplay" class="hidden bg-red-50 border border-red-200 rounded-xl p-4 text-red-700"></div>
    </section>

    <!-- Features Grid -->
    <section class="mb-8">
        <h2 class="text-xl font-bold text-gray-900 mb-4">Features</h2>
        <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div class="bg-white rounded-xl p-4 border border-amber-100 shadow-sm">
                <div class="text-center">
                    <i class="ri-checkbox-circle-line text-amber-600 ri-xl mb-2"></i>
                    <h4 class="font-semibold text-gray-900 text-sm">Format Check</h4>
                    <p class="text-xs text-gray-500">Syntax validation</p>
                </div>
            </div>
            <div class="bg-white rounded-xl p-4 border border-orange-100 shadow-sm">
                <div class="text-center">
                    <i class="ri-mail-send-line text-orange-600 ri-xl mb-2"></i>
                    <h4 class="font-semibold text-gray-900 text-sm">MX Records</h4>
                    <p class="text-xs text-gray-500">Mail server check</p>
                </div>
            </div>
            <div class="bg-white rounded-xl p-4 border border-yellow-100 shadow-sm">
                <div class="text-center">
                    <i class="ri-server-line text-yellow-600 ri-xl mb-2"></i>
                    <h4 class="font-semibold text-gray-900 text-sm">SMTP Check</h4>
                    <p class="text-xs text-gray-500">Mailbox verification</p>
                </div>
            </div>
            <div class="bg-white rounded-xl p-4 border border-red-100 shadow-sm">
                <div class="text-center">
                    <i class="ri-delete-bin-line text-red-600 ri-xl mb-2"></i>
                    <h4 class="font-semibold text-gray-900 text-sm">Disposable</h4>
                    <p class="text-xs text-gray-500">Temp mail detection</p>
                </div>
            </div>
            <div class="bg-white rounded-xl p-4 border border-purple-100 shadow-sm">
                <div class="text-center">
                    <i class="ri-alert-line text-purple-600 ri-xl mb-2"></i>
                    <h4 class="font-semibold text-gray-900 text-sm">Breach Check</h4>
                    <p class="text-xs text-gray-500">HIBP integration</p>
                </div>
            </div>
            <div class="bg-white rounded-xl p-4 border border-blue-100 shadow-sm">
                <div class="text-center">
                    <i class="ri-global-line text-blue-600 ri-xl mb-2"></i>
                    <h4 class="font-semibold text-gray-900 text-sm">WHOIS Info</h4>
                    <p class="text-xs text-gray-500">Domain details</p>
                </div>
            </div>
        </div>
    </section>

    <!-- API Endpoints -->
    <section class="mb-8">
        <h2 class="text-xl font-bold text-gray-900 mb-4">API Endpoints</h2>
        <div class="space-y-4">
            
            <!-- Single Email -->
            <div class="bg-white rounded-xl p-5 border border-gray-200 shadow-sm">
                <div class="flex items-center justify-between mb-3">
                    <h3 class="font-semibold text-gray-900">Single Email Check</h3>
                    <span class="px-3 py-1 bg-green-100 text-green-700 text-xs font-medium rounded-full">GET</span>
                </div>
                <div class="bg-gray-900 rounded-lg p-3 mb-3">
                    <code class="text-green-400 text-sm">/api/email?email={EMAIL}&smtp={true/false}</code>
                </div>
                <div class="bg-amber-50 rounded-lg p-3 border border-amber-200">
                    <p class="text-xs font-medium text-amber-900 mb-1">Example:</p>
                    <code class="text-xs text-amber-700">curl "https://api.example.com/api/email?email=test@gmail.com"</code>
                </div>
            </div>

            <!-- Batch Emails (Comma) -->
            <div class="bg-white rounded-xl p-5 border border-gray-200 shadow-sm">
                <div class="flex items-center justify-between mb-3">
                    <h3 class="font-semibold text-gray-900">Batch Check (Comma)</h3>
                    <span class="px-3 py-1 bg-green-100 text-green-700 text-xs font-medium rounded-full">GET</span>
                </div>
                <div class="bg-gray-900 rounded-lg p-3 mb-3">
                    <code class="text-green-400 text-sm">/api/email?email={EMAIL1},{EMAIL2}</code>
                </div>
                <div class="bg-amber-50 rounded-lg p-3 border border-amber-200">
                    <p class="text-xs font-medium text-amber-900 mb-1">Example:</p>
                    <code class="text-xs text-amber-700">curl "https://api.example.com/api/email?email=test@gmail.com,user@yahoo.com"</code>
                </div>
            </div>

            <!-- Batch Emails (POST) -->
            <div class="bg-white rounded-xl p-5 border border-gray-200 shadow-sm">
                <div class="flex items-center justify-between mb-3">
                    <h3 class="font-semibold text-gray-900">Batch Check (POST)</h3>
                    <span class="px-3 py-1 bg-orange-100 text-orange-700 text-xs font-medium rounded-full">POST</span>
                </div>
                <div class="bg-gray-900 rounded-lg p-3 mb-3">
                    <code class="text-green-400 text-sm">/api/batch</code>
                </div>
                <div class="bg-amber-50 rounded-lg p-3 border border-amber-200">
                    <p class="text-xs font-medium text-amber-900 mb-1">Request Body:</p>
                    <code class="text-xs text-amber-700">{"emails": ["test@gmail.com", "user@yahoo.com"], "smtp": false}</code>
                </div>
            </div>

        </div>
    </section>

    <!-- Sample Response -->
    <section class="mb-8 bg-white rounded-2xl p-6 shadow-sm border border-gray-200">
        <h2 class="text-xl font-bold text-gray-900 mb-4 flex items-center">
            <i class="ri-braces-line text-primary mr-2"></i>
            Sample Response
        </h2>
        <pre class="json-viewer text-xs">{
  "success": true,
  "email": "test@gmail.com",
  "is_valid_format": true,
  "username": "test",
  "domain": "gmail.com",
  "mx_records": [
    "gmail-smtp-in.l.google.com",
    "alt1.gmail-smtp-in.l.google.com"
  ],
  "has_mx": true,
  "smtp_deliverable": true,
  "smtp_message": "Mailbox exists",
  "is_disposable": false,
  "domain_registrar": "MarkMonitor Inc.",
  "domain_creation_date": "1995-08-13",
  "domain_country": "US",
  "breaches": ["Adobe", "LinkedIn", "MySpace"],
  "breach_count": 3,
  "checked_at": "2024-01-15 10:30:45 UTC",
  "checked_timestamp": 1705315245,
  "api_info": {
    "developed_by": "Creator Shyamchand & Ayan",
    "organization": "CEO & Founder Of - Nexxon Hackers",
    "version": "1.0.0"
  }
}</pre>
    </section>

    <!-- Developer Team Image -->
    <section class="mb-8">
        <div class="bg-gradient-to-br from-amber-100 to-orange-100 rounded-3xl p-6 border border-amber-200">
            <h3 class="text-lg font-bold text-gray-900 mb-4 text-center">Powered By Nexxon Hackers Team</h3>
            <img src="https://images.unsplash.com/photo-1522071820081-009f0129c71c?w=800&h=400&fit=crop" 
                 alt="Nexxon Hackers Development Team" 
                 class="w-full h-48 object-cover object-top rounded-xl shadow-md">
            <p class="text-center text-sm text-gray-600 mt-4">Our expert team building innovative solutions</p>
        </div>
    </section>

    <!-- Developer Credit -->
    <div class="text-center py-6">
        <div class="inline-block bg-gradient-to-r from-primary to-secondary text-white px-8 py-4 rounded-2xl shadow-lg">
            <p class="font-bold text-lg">Developed by Creator Shyamchand & Ayan</p>
            <p class="text-sm opacity-95">CEO & Founder Of - Nexxon Hackers</p>
        </div>
    </div>

</main>

<script>
function syntaxHighlight(json) {
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\\s*:)?|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?)/g, function (match) {
        var cls = 'json-number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'json-key';
                match = match.slice(0, -1) + '</span>:';
                return '<span class="' + cls + '">' + match;
            } else {
                cls = 'json-string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'json-boolean';
        } else if (/null/.test(match)) {
            cls = 'json-null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

document.getElementById('testBtn').addEventListener('click', async function() {
    const emailInput = document.getElementById('emailInput');
    const email = emailInput.value.trim();
    const smtpCheck = document.getElementById('smtpCheck').checked;
    
    if (!email) {
        alert('Please enter an email address');
        return;
    }
    
    const responseContainer = document.getElementById('responseContainer');
    const responseDisplay = document.getElementById('responseDisplay');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const errorDisplay = document.getElementById('errorDisplay');
    
    responseContainer.classList.add('hidden');
    errorDisplay.classList.add('hidden');
    loadingIndicator.classList.remove('hidden');
    
    try {
        const response = await fetch('/api/email?email=' + encodeURIComponent(email) + '&smtp=' + smtpCheck);
        const data = await response.json();
        
        loadingIndicator.classList.add('hidden');
        
        const jsonStr = JSON.stringify(data, null, 2);
        responseDisplay.innerHTML = syntaxHighlight(jsonStr);
        responseContainer.classList.remove('hidden');
        
    } catch (error) {
        loadingIndicator.classList.add('hidden');
        errorDisplay.textContent = 'Error: ' + error.message;
        errorDisplay.classList.remove('hidden');
    }
});

document.getElementById('copyBtn').addEventListener('click', function() {
    const responseDisplay = document.getElementById('responseDisplay');
    const text = responseDisplay.textContent;
    
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copyBtn');
        btn.innerHTML = '<i class="ri-check-line"></i> Copied!';
        setTimeout(() => {
            btn.innerHTML = '<i class="ri-file-copy-line"></i> Copy';
        }, 2000);
    });
});

document.getElementById('emailInput').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        document.getElementById('testBtn').click();
    }
});
</script>
</body>
</html>
'''

# ---------------- FLASK ROUTES ----------------
@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/email', methods=['GET'])
def email_lookup():
    email_param = request.args.get('email')
    smtp_param = request.args.get('smtp', 'false').lower() == 'true'
    
    if not email_param:
        return jsonify({
            "success": False,
            "error": "Missing 'email' parameter",
            "usage": {
                "endpoint": "/api/email?email=EMAIL&smtp=true/false",
                "example": "/api/email?email=test@gmail.com"
            },
            "api_info": {
                "developed_by": "Creator Shyamchand & Ayan",
                "organization": "CEO & Founder Of - Nexxon Hackers"
            }
        }), 400
    
    if ',' in email_param:
        emails = [e.strip() for e in email_param.split(',')]
        results = batch_lookup(emails, smtp_param)
        
        return jsonify({
            "success": True,
            "batch_mode": True,
            "total_requested": len(emails),
            "results": results,
            "api_info": {
                "developed_by": "Creator Shyamchand & Ayan",
                "organization": "CEO & Founder Of - Nexxon Hackers"
            }
        })
    
    result = get_email_info(email_param, smtp_param)
    
    if "api_info" not in result:
        result["api_info"] = {
            "developed_by": "Creator Shyamchand & Ayan",
            "organization": "CEO & Founder Of - Nexxon Hackers"
        }
    
    return jsonify(result)

@app.route('/api/batch', methods=['POST'])
def batch_email_lookup():
    try:
        data = request.get_json()
        
        if not data or 'emails' not in data:
            return jsonify({
                "success": False,
                "error": "Missing 'emails' array in request body",
                "example": {"emails": ["test@gmail.com", "user@yahoo.com"], "smtp": false},
                "api_info": {
                    "developed_by": "Creator Shyamchand & Ayan",
                    "organization": "CEO & Founder Of - Nexxon Hackers"
                }
            }), 400
        
        emails = data['emails']
        smtp_param = data.get('smtp', False)
        
        if not isinstance(emails, list):
            return jsonify({
                "success": False,
                "error": "'emails' must be an array",
                "api_info": {
                    "developed_by": "Creator Shyamchand & Ayan",
                    "organization": "CEO & Founder Of - Nexxon Hackers"
                }
            }), 400
        
        results = batch_lookup(emails, smtp_param)
        
        return jsonify({
            "success": True,
            "total_requested": len(emails),
            "results": results,
            "api_info": {
                "developed_by": "Creator Shyamchand & Ayan",
                "organization": "CEO & Founder Of - Nexxon Hackers"
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "api_info": {
                "developed_by": "Creator Shyamchand & Ayan",
                "organization": "CEO & Founder Of - Nexxon Hackers"
            }
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "Email Information API",
        "version": "1.0.0",
        "dns_available": DNS_AVAILABLE,
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "api_info": {
            "developed_by": "Creator Shyamchand & Ayan",
            "organization": "CEO & Founder Of - Nexxon Hackers"
        }
    })

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "success": False,
        "error": "Endpoint not found",
        "available_endpoints": {
            "home": "/",
            "single_email": "/api/email?email=EMAIL",
            "batch_get": "/api/email?email=EMAIL1,EMAIL2",
            "batch_post": "/api/batch (POST)",
            "health": "/api/health"
        },
        "api_info": {
            "developed_by": "Creator Shyamchand & Ayan",
            "organization": "CEO & Founder Of - Nexxon Hackers"
        }
    }), 404

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
