import resend
import os
import base64


# Set API key from environment variable


def send_message_email(sender_email, sender_app_password, receiver_email, subject, body):
    """
    sender_app_password kept only for backward compatibility.
    """
    resend.api_key = os.getenv("RESEND_API_KEY")
    try:
        email_data = {
            "from": sender_email,
            "to": [receiver_email],
            "subject": subject,
            "text": body,
        }

        return resend.Emails.send(email_data)

    except Exception as e:
        raise ValueError(f"error occur: {e}")


def send_assignment_email(sender_email, sender_app_password, receiver_email, subject, body, file_path):
    """
    Supports ANY file format: PDF, DOCX, XLSX, images, etc.
    Attachment is sent using Base64 encoding (required by Resend).
    """
    resend.api_key = os.getenv("RESEND_API_KEY")
    try:
        # Read file in binary mode
        with open(file_path, "rb") as f:
            file_data = f.read()
            file_name = os.path.basename(file_path)

        # Convert file bytes → Base64 text
        encoded_content = base64.b64encode(file_data).decode()

        email_data = {
            "from": sender_email,
            "to": [receiver_email],
            "subject": subject,
            "text": body,
            "attachments": [
                {
                    "filename": file_name,
                    "content": encoded_content,
                }
            ],
        }

        return resend.Emails.send(email_data)

    except Exception as e:
        raise ValueError(f"error occur: {e}")
