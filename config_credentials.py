import os
import hashlib
from dotenv import load_dotenv
load_dotenv() 
# Set the APP_SECRET_KEY environment variable
os.environ['APP_SECRET_KEY'] = hashlib.sha512(b'98r094uhdfkjhwkknqxjhiuhefwg').hexdigest()
os.environ['APP_EMAIL']="privex.official.contact@gmail.com"
os.environ['APP_EMAIL_CODE'] = "pbrp vfiq jijb gqwf"
# Access the APP_SECRET_KEY
APP_SECRET_KEY = os.environ.get('APP_SECRET_KEY')
print(f"APP_SECRET_KEY: {APP_SECRET_KEY}")