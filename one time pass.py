import hmac
import base64
import struct
import hashlib
import time
import secrets
import sys
import os
import getpass
import urllib.parse


can_use_pyqrcode = True
try:
    import pyqrcode
except ModuleNotFoundError:
    can_use_pyqrcode = False



def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h


def get_totp_token(secret):
    return get_hotp_token(secret, intervals_no = int(time.time()) // 30)


def generate_secret(length=16):
	random_secret = ""
	characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	for _ in range(length):
		random_secret += secrets.choice(characters)
	return random_secret


def format_secret(secret, to_length = 6):
	padded = '0'*(6-len(str(secret)))+str(secret)
	return padded[:3] + ' ' + padded[3:]


def setup_user():
    label = urllib.parse.quote(input("Label: "))
    user = urllib.parse.quote(input("User: "))
    secret = input("Auto-generate secret? y/n: ")
    
    if secret.lower() == "y":
    	secret = generate_secret()
    else: 
    	secret = input("Secret: ")
    	
    return label, user, secret


def show_qrcode(qr_url):
    url = pyqrcode.create(qr_url)
    os.system('cls' if os.name == 'nt' else 'clear')
    print(url.terminal(quiet_zone=1))


def loop(secret):
    sys.stdout.write("\r%s" % format_secret(get_totp_token(secret)))
    sys.stdout.flush()
    time.sleep(1 - time.time() % 1)

    while True:
        seconds = int(30 - time.time() % 30)
        lines = "-" * int(seconds)# / 3)
        blocks = "█" * (30 - len(lines))
        progress = "|" + blocks + lines + "|"

        sys.stdout.write("\r%s" % format_secret(get_totp_token(secret)) + "\t" + progress)
        sys.stdout.flush()

        time.sleep(1)


def setup_session():
    secret = "DID NOT SET SECRET"
    
    if input("Setup user? y/n: ").lower() == "y":
        label, user, secret = setup_user()
        
        qr_url = "otpauth://totp/%s:%s?secret=%s&issuer=%s" % (label, user, secret, label)
        if can_use_pyqrcode:
            if input("Show qr-code? y/n: ").lower().strip() == "y":
                show_qrcode(qr_url)
        else:
            print("You can generate a qr-code with this URL: ", qr_url)
    else:
        secret = getpass.getpass("Secret: ")
        os.system('cls' if os.name == 'nt' else 'clear')
    
    if secret == "DID NOT SET SECRET":
        print("INVALID SECRET")
        sys.exit(1)
    
    print("User secret: ", secret)
    
    loop(secret)


if __name__ == "__main__":
    setup_session()
