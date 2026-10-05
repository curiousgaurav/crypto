import io,json,os,secrets,sqlite3
from datetime import datetime,timedelta,timezone
from functools import wraps
import cv2,numpy as np,qrcode
from flask import Flask,flash,redirect,render_template,request,send_file,session,url_for
from werkzeug.security import check_password_hash,generate_password_hash
from crypto import decrypt_payload,encrypt_payload,load_or_create_signing_key
BASE=os.path.dirname(os.path.abspath(__file__)); DB=os.path.join(BASE,"cryptoqr.db"); KEY=os.path.join(BASE,"signing_key.pem")
app=Flask(__name__); app.secret_key=os.environ.get("FLASK_SECRET_KEY",secrets.token_hex(32)); signing_key=load_or_create_signing_key(KEY)
def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init_db():
 c=db(); c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE,password_hash TEXT,created_at TEXT)"); c.execute("CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,operation TEXT,fingerprint TEXT,created_at TEXT,expires_at TEXT,one_time INTEGER,used INTEGER DEFAULT 0)"); c.commit(); c.close()
def user():
 if not session.get("user_id"): return None
 c=db(); x=c.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone(); c.close(); return x
def login_required(f):
 @wraps(f)
 def w(*a,**k): return f(*a,**k) if user() else redirect(url_for("login"))
 return w
@app.route("/")
def index(): return redirect(url_for("dashboard") if user() else url_for("login"))
@app.route("/register",methods=["GET","POST"])
def register():
 if request.method=="POST":
  u=request.form["username"].strip(); p=request.form["password"]
  if len(u)<3 or len(p)<8: flash("Username 3+ chars and password 8+ chars required."); return render_template("register.html")
  try:
   c=db(); c.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",(u,generate_password_hash(p),datetime.now(timezone.utc).isoformat())); c.commit(); c.close(); flash("Registered successfully."); return redirect(url_for("login"))
  except sqlite3.IntegrityError: flash("Username already exists.")
 return render_template("register.html")
@app.route("/login",methods=["GET","POST"])
def login():
 if request.method=="POST":
  c=db(); x=c.execute("SELECT * FROM users WHERE username=?",(request.form["username"].strip(),)).fetchone(); c.close()
  if x and check_password_hash(x["password_hash"],request.form["password"]): session["user_id"]=x["id"]; return redirect(url_for("dashboard"))
  flash("Invalid username or password.")
 return render_template("login.html")
@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))
@app.route("/dashboard")
@login_required
def dashboard():
 c=db(); h=c.execute("SELECT * FROM messages WHERE user_id=? ORDER BY id DESC LIMIT 20",(session["user_id"],)).fetchall(); c.close(); return render_template("dashboard.html",user=user(),history=h)
@app.route("/encrypt",methods=["POST"])
@login_required
def encrypt():
 msg=request.form["message"]; pw=request.form["qr_password"]; mins=max(1,min(int(request.form.get("expiry_minutes",60)),10080)); one=request.form.get("one_time")=="on"
 if len(pw)<8: flash("QR password must be at least 8 characters."); return redirect(url_for("dashboard"))
 exp=(datetime.now(timezone.utc)+timedelta(minutes=mins)).isoformat(); payload=encrypt_payload(msg,pw,signing_key,exp,one)
 img=qrcode.make(json.dumps(payload,separators=(",",":"))); buf=io.BytesIO(); img.save(buf,format="PNG"); buf.seek(0)
 c=db(); c.execute("INSERT INTO messages(user_id,operation,fingerprint,created_at,expires_at,one_time) VALUES(?,?,?,?,?,?)",(session["user_id"],"ENCRYPT",payload["fingerprint"],datetime.now(timezone.utc).isoformat(),exp,int(one))); c.commit(); c.close()
 return send_file(buf,mimetype="image/png",as_attachment=True,download_name="cryptoqr_message.png")
def decode_qr(file):
 image=cv2.imdecode(np.frombuffer(file.read(),np.uint8),cv2.IMREAD_COLOR); text,_,_=cv2.QRCodeDetector().detectAndDecode(image)
 if not text: raise ValueError("No QR code detected"); return json.loads(text)
 return json.loads(text)
@app.route("/decrypt",methods=["POST"])
@login_required
def decrypt():
 try:
  payload=decode_qr(request.files["qr_file"]); now=datetime.now(timezone.utc); exp=payload.get("expires_at")
  if exp and now>=datetime.fromisoformat(exp): raise ValueError("QR code has expired")
  c=db(); used=c.execute("SELECT 1 FROM messages WHERE user_id=? AND operation='DECRYPT' AND fingerprint=? AND used=1",(session["user_id"],payload.get("fingerprint"))).fetchone()
  if payload.get("one_time") and used: raise ValueError("One-time QR has already been used")
  msg=decrypt_payload(payload,request.form["qr_password"])
  c.execute("INSERT INTO messages(user_id,operation,fingerprint,created_at,expires_at,one_time,used) VALUES(?,?,?,?,?,?,?)",(session["user_id"],"DECRYPT",payload["fingerprint"],now.isoformat(),exp,int(payload.get("one_time",False)),1)); c.commit(); c.close()
  return render_template("result.html",message=msg,payload=payload)
 except Exception as e: return render_template("result.html",error=str(e))
@app.route("/benchmark")
@login_required
def benchmark(): return render_template("benchmark.html")
if __name__=="__main__": init_db(); app.run(debug=True)
