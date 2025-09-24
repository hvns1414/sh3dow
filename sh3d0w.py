import os
import argparse
import hashlib
from cryptography.fernet import Fernet
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
print(r"""sh3dow/github.com/hvns1414/
      
      ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣭⣳⣶⣾⠟⢿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠘⢿⣶⣆⣀⠀⠀⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⢘⣿⣿⣯⣷⠶⠶⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⢿⣿⣿⣶⣦⣤⣤⣤⣤⣀⣠⣤⣤⣤⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣤⣴⣶⣿⣿⣿⣿⣿⣷⣄⠈⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣽⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠉⠙⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⡈⢻⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⣸⣧⠀⢻⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⢠⣿⣿⠀⠀⢻⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠛⠃⠘⠛⠃⠠⣤⣀⣛⣿⣯⣤⣴⣶⠀⣤⠸⣶⣆⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⣻⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠰⣦⣄⠀⠀⠀⠀⠀⢽⡿⢻⣻⣿⣶⣿⡇⢸⡁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠉⢷⣄⣠⣤⡾⠋⠀⢿⣷⣷⣿⣿⣇⣼⡇⠀⠀⠀⢀⡴
⠀⢰⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⡉⠀⠀⠀⠀⠀⣿⡿⠛⠻⠿⠋⠀⠀⠀⣠⠿⠁
⠀⠀⠉⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⡀⠀⠀⢠⣟⠁⠠⣤⣄⠀⠀⠀⡴⠋⠀⠀
⠀⠀⠀⠀⠀⠉⠙⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠋⢁⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣏⠀⠀⢀⣾⣿⣷⣦⣌⠉⢳⣄⡼⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⣾⣿⣿⣿⣿⣿⣷⣄⣿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣿⣿⣿⣿⣿⣿⣟⣿⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⠿⣿⣿⣿⣿⠛⢿⣿⣿⣿⣿⣿⣿⡏⠉⢿⣿⣿⣿⣾⣿⣿⣿⠏⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣷⣿⣿⣿⣿⣧⠀⣾⣿⣿⣿⣿⣿⣿⣇⠀⠀⠉⠉⠀⠉⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢁⣹⣿⣿⣿⣿⣿⣿⣾⣿⣿⡿⠛⢻⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠦⣄⣤⣾⠿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣷⢾⣿⣿⣿⡿⠀⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡶⠞⠛⠁⠀⣾⣿⣿⣿⠃⢀⡆⠀⢸⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⣀⣾⣿⣿⣿⡏⢠⡞⠀⠀⢸⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⡿⠛⠋⠀⠀⠀⢸⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣷⣦⡄⠀⠀⠀⢸⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⣸⣿⣿⣿⣿⣶⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠛⠛⠿⢿⣿⣿⣿⣿⣄⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⣄⣀⡀⠀⣤⣤⣼⡟⠓⣄⢸⣿⠿⠿⢿⢿⠿⠟⠛⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠸⣇⠀⠀⠀⠀⠀⢀⣀⣤⣾⣃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠟⠛⡛⠛⠛⢿⣿⣿⣿⣿⡇⣰⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠖⢦⣄⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡟⠀⢸⠡⠀⠀⢀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣦⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣅⠃⢨⡌⠀⠀⠸⢸⣿⣿⣿⢹⡟⠋⠢⢉⠻⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⢀⣰⡏⣿⣿⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠿⠷⠶⠶⠿⣿⣿⣿⠿⠟⠁⣾⠃⠀⠀⣀⠀⠈⠉⠛⠿⢿⣿⠿⣿⣧⣤⣶⠶⠶⠛⠋⣰⣿⡏⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣦⣆⣰⠟⠀⠀⠀⠀⠀⣰⣿⠀⠈⠻⢷⣤⣤⡶⠶⠾⠿⠋⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⠿⠶⣶⣿⡿⠷⠾⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⡀⠀⢀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
      
      
      """)
# ---------------------------
# Hash hesaplama
# ---------------------------
def calculate_hash(file_path, hash_type="sha256"):
    hash_func = getattr(hashlib, hash_type.lower())()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# ---------------------------
# Dosya şifreleme ve orijinali silme
# ---------------------------
def encrypt_file(file_path, key, delete_original=True):
    if not os.path.isfile(file_path):
        print(f"{file_path} is not a valid file!")
        return
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    enc_file = file_path + ".enc"
    with open(enc_file, "wb") as f:
        f.write(encrypted)
    hash_value = calculate_hash(enc_file)
    with open(enc_file + ".hash", "w") as f:
        f.write(hash_value)
    print(f"[+] Encrypted: {enc_file}")
    print(f"[+] Hash saved: {enc_file}.hash")
    if delete_original:
        os.remove(file_path)
        print(f"[+] Original file deleted: {file_path}")

def encrypt_folder(folder_path, key, delete_original=True):
    if not os.path.isdir(folder_path):
        print(f"{folder_path} is not a valid folder!")
        return
    for root, _, files in os.walk(folder_path):
        for file in files:
            encrypt_file(os.path.join(root, file), key, delete_original)

# ---------------------------
# Dosya şifre çözme
# ---------------------------
def decrypt_file(enc_file, key):
    if not os.path.isfile(enc_file):
        print(f"{enc_file} is not a valid file!")
        return
    hash_file = enc_file + ".hash"
    if not os.path.exists(hash_file):
        print(f"Hash file {hash_file} not found!")
        return
    with open(hash_file, "r") as f:
        saved_hash = f.read()
    current_hash = calculate_hash(enc_file)
    if saved_hash != current_hash:
        print("Hash mismatch! File may be tampered.")
        return
    fernet = Fernet(key)
    with open(enc_file, "rb") as f:
        encrypted_data = f.read()
    decrypted = fernet.decrypt(encrypted_data)
    dec_file = enc_file.replace(".enc", ".dec")
    with open(dec_file, "wb") as f:
        f.write(decrypted)
    print(f"[+] Decrypted: {dec_file}")
#migtag
# ---------------------------
# Tor tarayıcı başlatma (migta)
# ---------------------------
def start_tor_browser():
    options = Options()
    options.headless = False  # True yaparsan arka planda açılır

    # Proxy ve gizlilik ayarları
    options.set_preference('network.proxy.type', 1)
    options.set_preference('network.proxy.socks', '127.0.0.1')
    options.set_preference('network.proxy.socks_port', 9050)
    options.set_preference("places.history.enabled", False)
    options.set_preference("privacy.clearOnShutdown.offlineApps", True)
    options.set_preference("privacy.clearOnShutdown.passwords", True)
    options.set_preference("privacy.clearOnShutdown.siteSettings", True)
    options.set_preference("privacy.sanitize.sanitizeOnShutdown", True)
    options.set_preference("signon.rememberSignons", False)
    options.set_preference("network.cookie.lifetimePolicy", 2)
    options.set_preference("network.dns.disablePrefetch", True)
    options.set_preference("network.http.sendRefererHeader", 0)

    # Senin tarayıcı adın 'migta', profile olarak kullan
    profile_path = os.path.expanduser("~/shadow")
    if os.path.exists(profile_path):
        options.set_preference("profile", profile_path)

    driver = webdriver.Firefox(options=options)
    driver.get("https://check.torproject.org")
    print("[+] Tor browser opened!")
    return driver

# ---------------------------
# Ana program
# ---------------------------
parser = argparse.ArgumentParser(description="Tor browser (migta) + encrypt/decrypt tool")
parser.add_argument("-r", "--run_browser", action="store_true", help="Open Tor browser")
parser.add_argument("-s", "--source", help="File or folder to encrypt")
parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt file")
parser.add_argument("-k", "--key", help="Fernet key for encryption/decryption")

args = parser.parse_args()

# Tarayıcı çalıştır
if args.run_browser:
    start_tor_browser()

# Şifreleme / çözme
if args.source:
    if args.decrypt:
        if not args.key:
            print("[-] Decryption key required!")
        else:
            decrypt_file(args.source, args.key.encode())
    else:
        key = Fernet.generate_key()
        print(f"[+] Encryption key (save this!): {key.decode()}")
        if os.path.isfile(args.source):
            encrypt_file(args.source, key)
        elif os.path.isdir(args.source):
            encrypt_folder(args.source, key)
        else:
            print("[-] Invalid path.")
