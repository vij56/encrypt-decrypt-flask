from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

app = Flask(__name__)

# Generate a secret key for encryption and decryption.
# Keep this key safe; you'll need it for decryption.
SECRET_KEY = Fernet.generate_key()
cipher_suite = Fernet(SECRET_KEY)

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    data = request.get_json()
    print("data", "=======>", data)
    plaintext = data.get('data')
    print("plaintext", "=======>", plaintext)
    if not plaintext:
        return jsonify({"error": "Data not provided."}), 400
    
    encrypted_data = cipher_suite.encrypt(plaintext.encode())
    print("encrypted_data", "=======>", encrypted_data)
    print("encrypted_data.decode()", "=======>", encrypted_data.decode())
    return jsonify({"encrypted_data": encrypted_data.decode()})

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    data = request.get_json()
    print("data", "=======>", data)
    encrypted_data = data.get('encrypted_data')
    print("encrypted_data", "=======>", encrypted_data)
    if not encrypted_data:
        return jsonify({"error": "Encrypted data not provided."}), 400
    
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode()).decode()
        print("decrypted_data", "=======>", decrypted_data)
        return jsonify({"decrypted_data": decrypted_data})
    except Exception as e:
        return jsonify({"error": "Decryption failed."}), 400

if __name__ == '__main__':
    app.run(port=2222, debug=True)