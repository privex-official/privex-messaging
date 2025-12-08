
import smtplib
from email.message import EmailMessage
import os

def send_message_email(sender_email, sender_app_password, receiver_email, subject, body):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = receiver_email
        msg.set_content(body)

        # TLS connection (Port 587)
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.ehlo()
            server.starttls()
            server.login(sender_email, sender_app_password)
            server.send_message(msg)

        

    except Exception as e:
        raise ValueError(f"error occur: {e}")


def send_assignment_email(sender_email, sender_app_password, receiver_email, subject, body, file_path):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = receiver_email
        msg.set_content(body)

        # Attach the file
        with open(file_path, "rb") as f:
            file_data = f.read()
            file_name = os.path.basename(file_path)
            msg.add_attachment(file_data, maintype="application", subtype="octet-stream", filename=file_name)

        # SSL connection (Port 465)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, sender_app_password)
            smtp.send_message(msg)

        

    except Exception as e:
        raise ValueError(f"error occur: {e}")

