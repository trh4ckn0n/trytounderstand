from flask import Flask, render_template, request, send_file
import os, base64, random, string
from Crypto.Cipher import AES
from PIL import Image
from stegano import lsb

app = Flask(__name__)

greek_alphabet = ["Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta", "Iota", "Kappa", "Lambda", "Mu", "Nu", "Xi", "Omicron", "Pi", "Rho", "Sigma", "Tau", "Upsilon", "Phi", "Chi", "Psi", "Omega"]

def generate_key():
    return os.urandom(16)

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_message(key, encrypted_message):
    data = base64.b64decode(encrypted_message)
    nonce, ciphertext = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

def text_to_greek(text):
    return ' '.join([greek_alphabet[ord(c) % len(greek_alphabet)] for c in text])

def greek_to_text(greek_text):
    words = greek_text.split()
    return ''.join([chr(greek_alphabet.index(w) + 97) if w in greek_alphabet else '?' for w in words])

def hide_message_in_image(image_path, message, output_path):
    secret = lsb.hide(image_path, message)
    secret.save(output_path)

def reveal_message_from_image(image_path):
    return lsb.reveal(image_path)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = request.form['message']
    key = generate_key()
    encrypted_message = encrypt_message(key, message)
    return render_template('index.html', encrypted_message=encrypted_message, key=base64.b64encode(key).decode())

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_message = request.form['encrypted_message']
    key = base64.b64decode(request.form['key'])
    decrypted_message = decrypt_message(key, encrypted_message)
    return render_template('index.html', decrypted_message=decrypted_message)

@app.route('/steg/hide', methods=['POST'])
def steg_hide():
    message = request.form['steg_message']
    image = request.files['image']
    output_path = "static/hidden.png"
    image_path = "static/original.png"
    image.save(image_path)
    hide_message_in_image(image_path, message, output_path)
    return render_template('index.html', steg_image=output_path)

@app.route('/steg/reveal', methods=['POST'])
def steg_reveal():
    image = request.files['steg_image']
    image_path = "static/uploaded.png"
    image.save(image_path)
    hidden_message = reveal_message_from_image(image_path)
    return render_template('index.html', hidden_message=hidden_message)

if __name__ == '__main__':
    app.run(debug=True)
