from flask import Flask,redirect,url_for,render_template,request,session
from flask_mail import Mail, Message
import random
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from database import db
import bcrypt

app = Flask(__name__)
app.secret_key = 'notes@22'

s = URLSafeTimedSerializer(app.secret_key)

#https://myaccount.google.com/apppasswords

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'dasarirushindrareddy@gmail.com'
app.config['MAIL_PASSWORD'] = 'aopw ucln denc ygkb'
app.config['MAIL_DEFAULT_SENDER'] = 'dasarirushindrareddy@gmail.com'

mail = Mail(app)

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(name, email, otp):
    try:
        msg = Message('Your OTP Code', recipients=[email])
        msg.body = f"Hello {name}!\nYour OTP code is: {otp}"
        mail.send(msg)
        return True
    except Exception as e:
        print("Error sending email:", e)
        return False


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cursor = db.cursor()
        cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            return render_template('register.html', info ="This Email is already registered.")
        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
        db.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        cursor = db.cursor()
        cursor.execute("SELECT id, username, password, email, two_step, created_at FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = user[3]
            session['two_step'] = int(user[4])
            session['joined_at'] = user[5].strftime("%B %d, %Y")

            # Debug info
            print(f"[DEBUG] two_step = {session['two_step']} for {session['username']}")

            # ✅ Only send OTP if two_step = 1
            if session['two_step'] == 1:
                session['otp'] = generate_otp()
                print(f"[DEBUG] Generated OTP: {session['otp']}")
                if send_otp_email(session['username'], email, session['otp']):
                    return redirect(url_for('otp_verify'))
                else:
                    return render_template('login.html', info="Unable to send OTP.")
            else:
                session['Verified Login'] = True
                print("[DEBUG] Two-step OFF → Direct login to dashboard")
                return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', info="Invalid credentials.")

    return render_template('login.html')



@app.route('/forgotpassword',methods=['GET','POST'])
def forgotpassword():
    if request.method == 'POST':
        email = request.form.get('email')

        cursor = db.cursor()
        cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            session['email'] = email
            token=s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('resetpassword', token=token, _external=True)

            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_url}\n\nThis link will expire in 30 minutes.'
            mail.send(msg)

            return render_template('forgotpassword.html', msg="Password reset link has been sent to your email.") 

    return render_template('forgotpassword.html')

@app.route('/resetpassword/<token>', methods=['GET', 'POST'])
def resetpassword(token):
    try:
        # Decode the email from token
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  
    except SignatureExpired:
        return render_template('forgotpassword.html', info="Token expired. Request a new link.")
    
    if request.method == 'POST':
        newpassword = request.form.get("new_password")
        confirmpassword = request.form.get("confirm_password")

        if newpassword == confirmpassword:
            # ✅ Use decoded email instead of session
            hashed_password = bcrypt.hashpw(newpassword.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            cursor = db.cursor()
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
            db.commit()

            return redirect(url_for('login'))
        else:
            return render_template('resetpassword.html', info="Passwords do not match")

    return render_template('resetpassword.html', token=token)


@app.route('/otpverify',methods=['GET','POST'])
def otp_verify():
    if request.method == 'POST':
        enteredotp = request.form.get('otp')
        if enteredotp == session.get('otp'):
            session.pop('otp', None)
            session['Verified Login'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('otpverify.html',info="Invalid OTP. Please try again.")
        
    return render_template('otpverify.html')

@app.route('/toggle_two_step', methods=['POST'])
def toggle_two_step():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = db.cursor()

    # 🔄 Flip current two_step value directly in DB
    cursor.execute("UPDATE users SET two_step = 1 - two_step WHERE id = %s", (user_id,))
    db.commit()

    # ✅ Fetch updated two_step value
    cursor.execute("SELECT two_step FROM users WHERE id = %s", (user_id,))
    result = cursor.fetchone()
    cursor.close()

    # Update session
    session['two_step'] = int(result[0]) if result else 0
    print(f"[DEBUG] two_step toggled to {session['two_step']} for user_id {user_id}")

    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    print("Session two_step =", session.get('two_step'))

    if session.get('Verified Login') and session.get('user_id'):
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM notes WHERE user_id = %s ORDER BY created_at DESC", (session['user_id'],))
        notes = cursor.fetchall()
        return render_template('dashboard.html', username=session['username'], notes=notes)
    return redirect(url_for('login'))


@app.route('/createnote', methods=['POST'])
def create_note():
    if 'user_id' in session:
        title = request.form.get('title')
        content = request.form.get('content')
        user_id = session['user_id']
        cursor = db.cursor()
        cursor.execute("INSERT INTO notes (user_id, title, content) VALUES (%s, %s, %s)", (user_id, title, content))
        db.commit()
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/deletenote/<int:note_id>')
def deletenote(note_id):
    if 'user_id' in session:
        cursor = db.cursor()
        cursor.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
        db.commit()
    return redirect(url_for('dashboard'))

@app.route('/editnote/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cursor = db.cursor(dictionary=True)

    if request.method == 'POST':
        new_title = request.form.get('title')
        new_content = request.form.get('content')
        cursor.execute("UPDATE notes SET title=%s, content=%s WHERE id=%s AND user_id=%s", (new_title, new_content, note_id, session['user_id']))
        db.commit()
        cursor.close()
        return redirect(url_for('dashboard'))
        
    cursor.execute("SELECT * FROM notes WHERE id=%s AND user_id=%s", (note_id, session['user_id']))
    note = cursor.fetchone()
    cursor.close()
    if note:
        return render_template('editnote.html', note=note)
    
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
