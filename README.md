# AUTOMATED VULNERABILITY SCANNER

## Steps to run the project:

1. Clone this repo into the specified directory.
2. Ensure that virtualenv is installed and created (Replace <name> with anything.).
    - ```pip install virtualenv```
    - ```virtualenv <name>```
    - ```<name>\Scripts\activate``` (Windows) or ```source <name>\bin\activate``` (Unix/Bash)
3. Enter the following command to install dependencies :
    - ```pip install -r requirements.txt```
4. In database.py, provide username, encrypted password and its Fernet key. Ensure that database specified is created in MySQL/MariaDB.
   - For getting encrypted password and its Fernet key (Run in IPython (```pip install IPython```)) :
     ```
     from cryptography.fernet import Fernet #Ensure that cryptography package is installed.
     def encrypt_password(password):
         key = Fernet.generate_key()
         cipher_suite = Fernet(key)
         encrypted_password = cipher_suite.encrypt(password.encode())
         return encrypted_password.decode(), key.decode()
     
     print(encrypt_password("your_passwd"))
     ```
5. Run the following commands -
    - ```export FLASK_APP=app.py```
    - ```flask run```
      or
    - ```python app.py```
