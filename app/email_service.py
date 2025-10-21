import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_otp_email(email: str, otp: str):
    """Send OTP via email"""
    # Configure these with your email settings
    SMTP_SERVER = "smtp.gmail.com"  # Change to your SMTP server
    SMTP_PORT = 587
    SMTP_USERNAME = "lpx@lpxdigital.com"  # Change to your email
    SMTP_PASSWORD = "gwamaivffuvbhngr"  # Change to your app password
    
    try:
        message = MIMEMultipart()
        message["From"] = SMTP_USERNAME
        message["To"] = email
        message["Subject"] = "Password Reset OTP"
        
        body = f"""
        Hello,
        
        Your password reset OTP is: {otp}
        
        This OTP will expire in 10 minutes.
        
        If you didn't request this, please ignore this email.
        
        Best regards
        """
        
        message.attach(MIMEText(body, "plain"))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        print("Login Successfull")
        text = message.as_string()
        server.sendmail(SMTP_USERNAME, email, text)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False
