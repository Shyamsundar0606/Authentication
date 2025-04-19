import random
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText

# Temporary storage for OTPs
otp_store = {}

# Generate a random 3-digit OTP
def generate_otp():
    return random.randint(1000, 9999)

# Store the OTP with a timestamp
def create_otp(username):
    otp = generate_otp()
    otp_store[username] = {
        "otp": otp,
        "expires_at": datetime.now() + timedelta(seconds=90)  # OTP valid for 90 seconds
    }
    return otp

# Validate the OTP
def validate_otp(username, entered_otp):
    if username not in otp_store:
        return False, "No OTP generated."

    otp_data = otp_store[username]
    if datetime.now() > otp_data["expires_at"]:
        del otp_store[username]  # Clean up expired OTP
        return False, "OTP expired."

    if str(entered_otp) != str(otp_data["otp"]):
        return False, "Invalid OTP."

    # OTP is valid
    del otp_store[username]  # Clean up used OTP
    return True, "OTP validated."

# Send OTP via email
def send_otp_email(email, otp):
    sender_email = "authservice.projecttesting@gmail.com"  # Replace with your email
    sender_password = "txtxjyqakllwdnog"  # Use an app password for security
    subject = "Your OTP Code"
    body = f"Your OTP for login is {otp}. It is valid for 90 seconds."

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())
        print(f"OTP sent to {email}")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False
    
    
