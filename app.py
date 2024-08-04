from flask import Flask, request, render_template, redirect, url_for
import os
import fitz  # PyMuPDF
import re
import requests
import base64
from urllib.parse import urlparse
import socket
import hashlib

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['VT_API_KEY'] = ''  # Your VirusTotal API key

# Descriptions for PDF keywords
DESCRIPTIONS = {
    '/obj': 'Represents a PDF object.',
    '/endobj': 'Marks the end of a PDF object.',
    '/stream': 'Begins a stream object, which can contain image data or other binary data.',
    '/endstream': 'Marks the end of a stream object.',
    '/xref': 'Cross-reference table, which is used to locate objects within the PDF file.',
    '/trailer': 'Contains information needed to open the file, including the root object, size of the file, etc.',
    '/startxref': 'Marks the beginning of the cross-reference table.',
    '/Page': 'Indicates a page object, which contains content such as text, images, etc.',
    '/Encrypt': 'Indicates that the PDF file is encrypted.',
    '/ObjStm': 'Object streams, which can be used to store multiple PDF objects in a single stream.',
    '/JS': 'Indicates embedded JavaScript code.',
    '/JavaScript': 'Indicates embedded JavaScript code.',
    '/AA': 'Additional actions, which can be triggered by events such as opening or closing the document.',
    '/OpenAction': 'Specifies an action to be performed when the document is opened.',
    '/JBIG2Decode': 'Used for decoding JBIG2-encoded data, which is a highly compressed image format.',
    '/RichMedia': 'Embedded multimedia content such as video or sound.',
    '/Launch': 'Specifies an action to launch an external application or script.',
    '/XFA': 'XML Forms Architecture, used for interactive forms.',
    '/FDF': 'Form Data Format, which can be exploited to embed malicious payloads.',
    '/SubmitForm': 'A type of action that can be used to send data to a remote server.',
    '/EmbeddedFile': 'Indicates an embedded file within the PDF.',
    '/URI': 'Indicates an embedded URL within the PDF.'
}

KEYWORDS = list(DESCRIPTIONS.keys())

def extract_raw_pdf_content(filepath):
    """Extract raw PDF content including all objects and streams."""
    with open(filepath, 'rb') as f:
        return f.read()

def extract_keywords_from_raw_content(raw_content):
    """Count occurrences of keywords in the raw PDF content."""
    occurrences = {keyword: raw_content.count(keyword.encode()) for keyword in KEYWORDS}
    return occurrences

def extract_urls_from_pdf(pdf_text):
    urls = re.findall(r'https?://\S+', pdf_text)
    print(f"Extracted URLs: {urls}")  # Debugging line
    return urls

def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def scan_url_virustotal(api_key, url):
    try:
        # Encode URL for VirusTotal API
        encoded_url = encode_url(url)
        vt_url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'

        headers = {
            'x-apikey': api_key
        }

        response = requests.get(vt_url, headers=headers)

        if response.status_code == 200:
            response_json = response.json()
            if 'data' in response_json:
                analysis_result = response_json['data']
                attributes = analysis_result.get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})

                if last_analysis_stats.get('malicious', 0) > 0:
                    return 'Malicious'
                elif last_analysis_stats.get('suspicious', 0) > 0:
                    return 'Suspicious'
                else:
                    return 'Clean'
            else:
                return 'No Analysis Data'
        else:
            return f'APIError: {response.status_code} - {response.text}'

    except requests.RequestException as e:
        print(f"RequestException scanning URL {url}: {e}")
        return f'Error: {e}'
    except Exception as e:
        print(f"Error scanning URL {url}: {e}")
        return f'Error: {e}'

def get_ip_from_url(url):
    """Extract IP address from URL."""
    try:
        hostname = urlparse(url).hostname
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        print(f"Error getting IP from URL {url}: {e}")
        return None

def get_geo_location(ip_address):
    """Get geo-location info from IP address."""
    if ip_address:
        try:
            response = requests.get(f'http://ip-api.com/json/{ip_address}')
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'Error {response.status_code}'}
        except requests.RequestException as e:
            print(f"RequestException getting geo-location for IP {ip_address}: {e}")
            return {'error': str(e)}
    return {'error': 'No IP address'}

def generate_hex_dump(filepath, num_lines=7):
    """Generate a hex dump of the PDF file, limited to a specific number of lines."""
    with open(filepath, 'rb') as f:
        hex_dump = []
        while (line := f.read(16)):
            hex_line = ' '.join(f'{byte:02X}' for byte in line)
            hex_dump.append(hex_line)
            if len(hex_dump) >= num_lines:
                break
    return hex_dump

def generate_object_dump(raw_content, num_lines=7):
    """Generate an object dump of the raw PDF content, limited to a specific number of lines."""
    object_dump = []
    lines = raw_content.splitlines()
    for line in lines:
        if any(keyword.encode() in line for keyword in KEYWORDS):
            object_dump.append(line.decode('utf-8', errors='ignore'))
            if len(object_dump) >= num_lines:
                break
    return object_dump

def calculate_hashes(filepath):
    """Calculate MD5, SHA1, and SHA256 hashes for the file."""
    hashes = {'MD5': None, 'SHA1': None, 'SHA256': None}
    with open(filepath, 'rb') as f:
        file_data = f.read()
        hashes['MD5'] = hashlib.md5(file_data).hexdigest()
        hashes['SHA1'] = hashlib.sha1(file_data).hexdigest()
        hashes['SHA256'] = hashlib.sha256(file_data).hexdigest()
    return hashes

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))

    if file and file.filename.endswith('.pdf'):
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return redirect(url_for('analyze', filename=filename))

    return redirect(url_for('index'))

@app.route('/analyze/<filename>')
def analyze(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        return "File not found.", 404

    pdf_text = ""
    metadata = {}
    pdf_info = {}
    url_scan_results = {}
    ip_geo_info = {}
    hex_dump = []
    object_dump = []
    file_hashes = {}

    try:
        # Extract raw PDF content
        raw_content = extract_raw_pdf_content(filepath)
        pdf_info = extract_keywords_from_raw_content(raw_content)
        
        # Generate hex and object dumps
        hex_dump = generate_hex_dump(filepath, num_lines=7)
        object_dump = generate_object_dump(raw_content, num_lines=7)
        
        # Print hex and object dumps for debugging
        print(f"Hex Dump:\n{hex_dump}")
        print(f"Object Dump:\n{object_dump}")

        # Extract text using PyMuPDF
        doc = fitz.open(filepath)
        pdf_text = "\n".join(page.get_text("text") for page in doc)
        print(f"Extracted PDF Text Preview: {pdf_text[:1000]}")  # Debugging line
        metadata = doc.metadata
        
        # Extract URLs from text
        urls = extract_urls_from_pdf(pdf_text)

        # Extract URLs from annotations
        for page_num in range(len(doc)):
            page = doc.load_page(page_num)
            links = page.get_links()
            for link in links:
                if 'uri' in link:
                    urls.append(link['uri'])

        # Remove duplicates
        urls = list(set(urls))

        if not urls:
            print("No URLs found in the PDF.")  # Debugging line

        for url in urls:
            result = scan_url_virustotal(app.config['VT_API_KEY'], url)
            ip_address = get_ip_from_url(url)
            geo_info = get_geo_location(ip_address)
            url_scan_results[url] = {'result': result}
            ip_geo_info[url] = geo_info

        # Calculate file hashes
        file_hashes = calculate_hashes(filepath)

    except Exception as e:
        print(f"Exception occurred during PDF analysis: {e}")  # Debugging line
        return str(e), 500

    return render_template('result.html', pdf_info=pdf_info, metadata=metadata, url_scan_results=url_scan_results, descriptions=DESCRIPTIONS, ip_geo_info=ip_geo_info, hex_dump=hex_dump, object_dump=object_dump, file_hashes=file_hashes)

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
