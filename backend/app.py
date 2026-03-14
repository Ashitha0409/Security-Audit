from dotenv import load_dotenv
load_dotenv()  # Load .env file before anything else

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import urlparse
import os, sys, re, logging

sys.path.insert(0, os.path.dirname(__file__))
from scanner import run_full_scan
from report_generator import generate_pdf_report

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')

# Restrict CORS to your own domain in production
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*')
if ALLOWED_ORIGINS == '*':
    CORS(app)  # dev: allow all
else:
    CORS(app, origins=ALLOWED_ORIGINS.split(','))

# Rate limiting — max 5 scans/min per IP
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)


@app.route('/')
def index():
    return render_template('index.html')


# Single /scan route (was duplicated before — second one was silently ignored)
@app.route('/scan', methods=['POST'])
@limiter.limit("5 per minute")
def scan():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON body'}), 400

    url = data.get('url', '').strip().rstrip('/')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # If user typed multiple URLs, take only the first one
    url = url.split()[0]

    # Add https:// if missing
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    # Basic validation
    hostname = urlparse(url).hostname or ''
    if '.' not in hostname:
        return jsonify({'error': 'Please enter a valid website URL (e.g. https://yoursite.com)'}), 400

    logger.info(f"Scan requested for: {hostname}")

    try:
        result = run_full_scan(url)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Scan failed for {hostname}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/generate-report', methods=['POST'])
@limiter.limit("10 per minute")
def generate_report():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON body'}), 400
    try:
        reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        filename = generate_pdf_report(data, reports_dir)
        if filename:
            return jsonify({'filename': filename, 'url': f'/report/{filename}'})
        return jsonify({'error': 'PDF generation failed - install reportlab'}), 500
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/report/<path:filename>')
def download_report(filename):
    # Validate filename to prevent directory traversal attacks
    if not re.match(r'^[\w\-\.]+\.pdf$', filename):
        return jsonify({'error': 'Invalid filename'}), 400

    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    return send_from_directory(reports_dir, filename, as_attachment=True)


# debug=True only when explicitly set via env var (never in production)
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting PRAWL on port {port} (debug={debug_mode})")
    app.run(debug=debug_mode, port=port)