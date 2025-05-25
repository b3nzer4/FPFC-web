from flask import Flask, render_template, request, send_file, jsonify
from cryptography.fernet import Fernet
import os
import base64
from werkzeug.utils import secure_filename
import io
from datetime import datetime, timedelta

app = Flask(__name__)

# Store encrypted files in memory with expiration
encrypted_files = {}
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25MB limit

def is_valid_key(key):
    try:
        # Kiểm tra xem key có phải là base64 hợp lệ không
        base64.b64decode(key)
        return True
    except:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return jsonify({'error': 'Không tìm thấy file'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Không có file được chọn'}), 400
    
    key = request.form.get('key', '')
    if not key or not is_valid_key(key):
        return jsonify({'error': 'Key không hợp lệ'}), 400

    try:
        # Lấy tên file và đuôi file
        filename = secure_filename(file.filename)
        name, extension = os.path.splitext(filename)
        extension = extension[1:]  # Bỏ dấu chấm ở đầu đuôi file
        
        # Tạo tên file mới với format: tênfile(đuôi).bin
        encrypted_filename = f"{name}({extension}).bin"

        # Đọc và mã hóa file
        file_data = file.read()
        f = Fernet(key.encode())
        encrypted_data = f.encrypt(file_data)

        # Lưu file đã mã hóa vào bộ nhớ với thời gian hết hạn
        encrypted_files[encrypted_filename] = {
            'data': encrypted_data,
            'expires': datetime.now() + timedelta(minutes=5)  # File sẽ tự động xóa sau 5 phút
        }

        return jsonify({'filename': encrypted_filename})

    except Exception as e:
        return jsonify({'error': f'Lỗi khi mã hóa file: {str(e)}'}), 500

@app.route('/download/<filename>')
def download(filename):
    try:
        filename = secure_filename(filename)
        
        # Kiểm tra xem file có tồn tại trong bộ nhớ không
        if filename not in encrypted_files:
            return jsonify({'error': 'File không tồn tại hoặc đã hết hạn'}), 404
            
        file_data = encrypted_files[filename]
        
        # Kiểm tra xem file có hết hạn chưa
        if datetime.now() > file_data['expires']:
            del encrypted_files[filename]
            return jsonify({'error': 'File đã hết hạn'}), 410
        
        # Tạo BytesIO object từ dữ liệu đã mã hóa
        file_stream = io.BytesIO(file_data['data'])
        
        # Gửi file
        response = send_file(
            file_stream,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
        
        # Xóa file sau khi gửi xong
        @response.call_on_close
        def delete_file():
            if filename in encrypted_files:
                del encrypted_files[filename]
        
        return response
        
    except Exception as e:
        return jsonify({'error': f'Lỗi khi tải file: {str(e)}'}), 500

# For Vercel deployment
app = app 