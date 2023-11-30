import smtplib
import ssl
from email.message import EmailMessage
from email_constants import email_sender,email_password,subject

def send_email(email_sender, email_password, email_receiver, subject, body):
    try:
        em = EmailMessage()
        em['From'] = email_sender
        em['To'] = email_receiver
        em['Subject'] = subject
        em.set_content(body)

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, email_password)
            smtp.sendmail(email_sender, email_receiver, em.as_string())
        print("Email sent successfully!")

    except smtplib.SMTPAuthenticationError as auth_error:
        print(f"SMTP Authentication Error: {auth_error}")
    except smtplib.SMTPException as smtp_error:
        print(f"SMTP Exception: {smtp_error}")
    except ssl.SSLError as ssl_error:
        print(f"SSL Error: {ssl_error}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def send_email_to_approver(approver_email, requestor_id, requestor_username, reason_for_access, access_duration, secret_share):
    body = f"""Dear Approver,
        
Requestor ID: {requestor_id}
Requestor Username: {requestor_username}
Reason For Access: {reason_for_access}
Access Duration: {access_duration} minutes
Secret Share:  {secret_share}
                    
Please copy the secret share and use it to approve the PAM request via this link: <a href="http://localhost:5000/testing">Approve PAM request</a>"""
        
    # Send the email with the body to this approver
    send_email(email_sender,email_password,approver_email,subject,body)


        




