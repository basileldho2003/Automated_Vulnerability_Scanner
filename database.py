import pytz

from sqlalchemy import Boolean, ForeignKey, create_engine, Column, Integer, String, Text, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import *
from cryptography.fernet import Fernet

def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key.encode())
    decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
    return decrypted_password.decode()

def get_ist_time():
    utc_time = datetime.now(timezone.utc)
    ist_time = utc_time.replace(tzinfo=pytz.utc).astimezone(pytz.timezone('Asia/Kolkata'))
    return ist_time

user=""
#Refer to readme for MySQL/MariaDB password encryption (Fernet implementation). 
myepasswd="" #Encrypted password
mykey="" #Encrypted Fernet key
dpasswd=decrypt_password(myepasswd, mykey)
DATABASE_URL = f"mysql+mysqlconnector://{user}:{dpasswd}@localhost/vuln_scanner"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Target(Base):
    __tablename__ = 'targets'
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(255), nullable=False)
    created_at = Column(TIMESTAMP, default=get_ist_time)
    username = Column(String(50), ForeignKey('users.username'))
    is_scanned = Column(Boolean, default=False)

class ScanResult(Base):
    __tablename__ = 'scan_results'
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey('targets.id'))
    target_url = Column(String(255))
    vulnerability_type = Column(String(255))
    description = Column(Text)
    remediation = Column(Text)
    found_at = Column(TIMESTAMP, default=get_ist_time)
    username = Column(String(50), ForeignKey('users.username'))

class Users(Base):
    __tablename__ = 'users'
    username = Column(String(5), primary_key=True)
    passwd = Column(String(512))

Base.metadata.create_all(bind=engine)