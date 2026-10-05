# CryptoQR Advanced

Advanced Secure QR Communication System.

Crypto protocol: Argon2id password KDF, random per-message AES-256 session key, AES key wrapping, AES-256-GCM authenticated encryption, SHA3-256 fingerprint, ECDSA P-256 signatures, expiration and one-time QR controls.

Run on PowerShell:

python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py


