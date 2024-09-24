import os
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import hashlib
import magic
import yara
import requests
from dotenv import load_dotenv

app = Flask(__name__)

# Load environment variables
load_dotenv()

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'exe', 'dll', 'doc', 'docx', 'pdf', 'js', 'vbs', 'ps1', 'zip', 'rar', 'jpg', 'png', 'txt'}
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
YARA_RULES_PATH = os.getenv('YARA_RULES_PATH', 'path/to/your/yara/rules.yar')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        return f"Error calculating hash: {str(e)}"

def get_file_type(file_path):
    try:
        return magic.from_file(file_path, mime=True)
    except Exception as e:
        return f"Error determining file type: {str(e)}"

def scan_with_yara(file_path):
    try:
        rules = yara.compile(YARA_RULES_PATH)
        matches = rules.match(file_path)
        return [match.rule for match in matches]
    except Exception as e:
        return f"Error scanning with YARA: {str(e)}"

def scan_with_virustotal(file_hash):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        return result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    except requests.RequestException as e:
        return f"Error scanning with VirusTotal: {str(e)}"

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No file selected for uploading"}), 400
    
    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            file_hash = calculate_hash(file_path)
            file_type = get_file_type(file_path)
            yara_results = scan_with_yara(file_path)
            virustotal_results = scan_with_virustotal(file_hash)
            
            analysis_result = {
                "filename": filename,
                "hash": file_hash,
                "file_type": file_type,
                "yara_matches": yara_results,
                "virustotal_results": virustotal_results
            }
            
            # Clean up the uploaded file
            os.remove(file_path)
            
            return jsonify(analysis_result)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify({"error": f"File type not allowed. Allowed types are: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": "File too large. Maximum file size is 16 MB."}), 413

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=False)