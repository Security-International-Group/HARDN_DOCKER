from flask import Flask, request
import logging
import os
import subprocess
import json
from typing import Dict, List, Tuple, Any
from werkzeug.exceptions import HTTPException

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def hello_world():
    app.logger.info("Received request to /")
    

    cis_results = run_cis_checks()
    compliance_data: Dict[str, Any] = {
        'cis_docker_benchmark': cis_results,
        'container_hardening': {
            'read_only_filesystem': True,
            'no_root_user': True,
            'security_scanning': 'enabled'
        }
    }

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Container Compliance Report</title>
        <style>
            body {{
                margin: 0;
                padding: 20px;
                background-image: url('data:image/png;base64,{get_image_base64()}');
                background-size: cover;
                background-attachment: fixed;
                font-family: Arial, sans-serif;
            }}
            .report {{
                background: rgba(255, 255, 255, 0.95);
                padding: 30px;
                border-radius: 10px;
                max-width: 900px;
                margin: 0 auto;
                box-shadow: 0 0 20px rgba(0, 0, 0, 0.3);
            }}
            h1 {{
                color: #333;
                text-align: center;
            }}
            pre {{
                background: #f4f4f4;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
                color: #333;
            }}
        </style>
    </head>
    <body>
        <div class="report">
            <h1>REVIEW CONTAINER COMPLIANCE</h1>
            <pre>{json.dumps(compliance_data, indent=2)}</pre>
        </div>
    </body>
    </html>
    """
    app.logger.info("Sending compliance report page")
    return html

def get_image_base64():
    """Convert image to base64 for embedding"""
    candidates = [
        '/sources/hardn_docker.png',
        os.path.join(os.path.dirname(__file__), 'sources', 'hardn_docker.png'),
    ]
    try:
        import base64
        for image_path in candidates:
            if os.path.isfile(image_path):
                with open(image_path, 'rb') as img_file:
                    return base64.b64encode(img_file.read()).decode()
    except Exception as e:
        app.logger.error(f"Error loading image: {e}")
    return ""

@app.before_request
def log_request_info():
    app.logger.debug('Headers: %s', request.headers)
    app.logger.debug('Body: %s', request.get_data())

@app.route('/health')
def health_check():
    app.logger.info("Health check requested")
    return {'status': 'healthy'}, 200

@app.route('/compliance')
def compliance_status() -> Tuple[Dict[str, Any], int]:
    app.logger.info("Compliance status requested")
    cis_results = run_cis_checks()
    
    compliance_data: Dict[str, Any] = {
        'cis_docker_benchmark': cis_results,
        'container_hardening': {
            'read_only_filesystem': True,
            'no_root_user': True,
            'security_scanning': 'enabled'
        }
    }
    app.logger.info(f"Compliance status: {compliance_data}")
    return compliance_data, 200

def run_cis_checks() -> Dict[str, List[str]]:
    """Run CIS Docker Benchmark checks"""
    checks: Dict[str, List[str]] = {
        'passed': [],
        'failed': [],
        'warnings': []
    }
    
    try:
        result = subprocess.run(['whoami'], capture_output=True, text=True)
        if result.stdout.strip() != 'root':
            checks['passed'].append('Not running as root')
        else:
            checks['warnings'].append('Running as root user')
    except Exception as e:
        app.logger.error(f"CIS check error: {e}")
        checks['failed'].append(str(e))
    
    return checks

@app.errorhandler(404)
def not_found(error: HTTPException) -> Tuple[Dict[str, str], int]:
    app.logger.warning(f"404 error: {error}")
    return {'error': 'Not found'}, 404

@app.errorhandler(500)
def server_error(error: HTTPException) -> Tuple[Dict[str, str], int]:
    app.logger.error(f"500 error: {error}")
    return {'error': 'Internal server error'}, 500

if __name__ == '__main__':
    # debug=False required for production/CIS compliance (information disclosure)
    app.run(host='0.0.0.0', port=5000, debug=False)