"""send mail using mailgun
"""
# standard
from os import getenv

# pypi
from mailgun.client import Client

def sendmail(from_addr, to_addrs, subject, body, **kwargs):
    key = getenv('MAILGUN_API_KEY')
    domain = getenv('MAILGUN_DOMAIN')
    client = Client(auth=("api", key))

    try:
        # Create the email message
        data = {
            "from": from_addr,
            "to": to_addrs,
            "subject": subject,
            "text": body
        }

        req = client.messages.create(domain=domain, data=data, **kwargs)
        
    except Exception as e:
        print(f"Error sending email: {e}")# Email credentials and details
        raise
