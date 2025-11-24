from flask import Flask,redirect,url_for
import random

app = Flask(__name__)

login_status=False

mails=['tarak@gmail.com','dinesh@gmail.com','sanjay@gmail.com','rushi@gmail.com']
mail=random.choice(mails)

print("mail:*******************",mail)

@app.route('/')
def home():
    if login_status:
        return f"Hello !  \n Welcome to the Notes Management System."
    else:
        return redirect(url_for('resetpassword',mail=mail))

@app.route('/register')
def register():
    return "This is the Register Page"

@app.route('/login')
def login():
    return "This is the Login Page"

@app.route('/forgotpassword')
def forgot_password():
    return "This is the Forgot Password Page"

@app.route('/resetpassword/<mail>')
def reset_password(mail):
    if mail in mails:
        return f"Hello {mail.split('@')[0]}!!  \n You can reset your Password."
    else:
        return f"The User : {mail.split('@')[0]} is not avaliable in database."


@app.route('/otpverify')
def otp_verify():
    return "This is the OTP Verify Page"

if __name__ == '__main__':
    app.run(debug=True)
