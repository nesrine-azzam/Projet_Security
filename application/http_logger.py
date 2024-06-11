import time
from datetime import datetime
import re
import urllib.parse
import base64
from functools import wraps
from flask import request, abort, Flask
import logging
import re
from scapy.all import *
from googleapiclient.discovery import build
from email.mime.text import MIMEText
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import base64
import os

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

creds = None

current_dir = os.path.dirname(os.path.abspath(__file__))

if os.path.exists(os.path.join(current_dir, 'token.json')):
    creds = Credentials.from_authorized_user_file(os.path.join(current_dir, 'token.json'))
else:
    flow = InstalledAppFlow.from_client_secrets_file(
        os.path.join(current_dir, 'credentials.json'), SCOPES)
    creds = flow.run_local_server(port=0)
    # Save the credentials for the next run
    with open(os.path.join(current_dir, 'token.json'), 'w') as token:
        token.write(creds.to_json())


# Dictionnaire pour stocker les tentatives de connexion échouées
failed_attempts = {}

# Dictionnaire pour stocker les tentatives de connexion échouées par IP
# failed_attempts_by_ip = {}

# Nombre de tentatives de connexion échouées autorisées avant le blocage
max_attempts = 5

# Temps en secondes avant qu'une tentative de connexion échouée expire
block_duration = 8

# Dictionnaire pour stocker les adresses IP bloquées et leurs temps de déblocage
blocked_ips = {}

# Expression régulière pour détecter les injections SQL

# Regex V2 (+Puissant) from: https://regex101.com/library/qE9gR7
sql_injection_pattern = re.compile(r"\s*([\0\b\'\"\n\r\t\%\_\\]*\s*(((select\s*.+\s*from\s*.+)|(insert\s*.+\s*into\s*.+)|(update\s*.+\s*set\s*.+)|(delete\s*.+\s*from\s*.+)|(drop\s*.+)|(truncate\s*.+)|(alter\s*.+)|(exec\s*.+)|(\s*(all|any|not|and|between|in|like|or|some|contains|containsall|containskey)\s*.+[\=\>\<=\!\~]+.+)|(let\s+.+[\=]\s*.*)|(begin\s*.*\s*end)|(\s*[\/\*]+\s*.*\s*[\*\/]+)|(\s*(\-\-)\s*.*\s+)|(\s*(contains|containsall|containskey)\s+.*)))(\s*[\;]\s*)*)+")

# Durée de blocage en secondes
block_duration_ip = 300


# Récupére la date et l'heure actuelles
now = datetime.now()
current_time = now.strftime("%d/%m/%Y %H:%M:%S")

# Adresse mail de reception des avertissement d'attaque
mail_receptor = os.getenv('MAIL_RECEPTOR', "jorgearturo@live.fr")

def send_email(subject, body, to):
    service = build('gmail', 'v1', credentials=creds)

    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes())
    raw_message = raw_message.decode()
    message = service.users().messages().send(userId="me", body={"raw": raw_message}).execute()

def is_ip_blocked(client_ip):
    if client_ip in blocked_ips:
        block_expiration_time = blocked_ips[client_ip]
        if time.time() < block_expiration_time:
            return True
        else:
            del blocked_ips[client_ip]
            return False
    return False

def block_ip(client_ip):
    blocked_ips[client_ip] = time.time() + block_duration_ip

def decode_encoded_string(input_string):
    decoded_string = input_string
    # Décoder l'encodage URL
    try:
        decoded_string = urllib.parse.unquote(decoded_string)
    except Exception:
        pass

    # Décoder l'encodage Base64
    try:
        decoded_string = base64.b64decode(decoded_string).decode('utf-8')
    except Exception:
        pass

    return decoded_string

def detect_bruteforce_attack(username):
    current_time = int(time.time())
    if username not in failed_attempts:
        failed_attempts[username] = [current_time]
    else:
        # Enleve les tentatives qui sont plus anciennes que la durée du bloc.
        failed_attempts[username] = [t for t in failed_attempts[username] if current_time - t < block_duration]
        failed_attempts[username].append(current_time)

    # Si le nombre de tentatives échouées dans le bloc de temps dépasse le maximum autorisé,
    # alors nous considérons cela comme une attaque brute force.
    if len(failed_attempts[username]) >= max_attempts:
        return True
    return False

def detect_xss(input_string):
    # XSS Regex V2
    xss_pattern = r'(\b)(on\S+)(\s*)=|javascript|<(|\/|[^\/>][^>]+|\/[^>][^>]+)>'
    return bool(re.search(xss_pattern, input_string))

def detect_sql_injection(input_data):
    decoded_input_data = decode_encoded_string(input_data)
    if sql_injection_pattern.search(input_data):
        return True
    elif sql_injection_pattern.search(decoded_input_data):
        return True
    return False

def detect_cybersecurity_agents(user_agent):
    cybersecurity_agents = ['nikto', 'burp', 'metasploit']
    user_agent = user_agent.lower()
    return any(agent in user_agent for agent in cybersecurity_agents)

def detect_metasploit(pkt):
    if TCP in pkt:
        client_ip = request.remote_addr
        if pkt[TCP].dport == 4444 or pkt[TCP].dport == 4445:
            if "metasploit" in str(pkt[TCP].payload).lower():
                print("Metasploit traffic detected!")          
                logging.warning(f"Cybersecurity agent Metasploit detected from IP '{client_ip}'")
                block_ip(client_ip)
                abort(400, description="Access denied.")


def log_and_protect(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        if is_ip_blocked(client_ip):
            logging.warning(f"This IP: '{client_ip}' try to connect againt to this Account: '{username}'")
            send_email(subject="Attack attempt detected from your APP: Maybe DDOS",body=f"Attack DDOS detected on your APP from This IP: {client_ip} at {current_time}, be carefull",to=mail_receptor)
            abort(429, description="Your IP is temporarily blocked. Please try again later.")

        if username and password:

            if detect_cybersecurity_agents(user_agent):
                logging.warning(f"Cybersecurity agent '{user_agent}' detected from IP '{client_ip}'")
                send_email(subject="Attack attempt detected from your APP: Maybe Cyber Agent",body=f"Cybersecurity agent {user_agent} detected on your APP from This IP: {client_ip} at {current_time}, be carefull",to=mail_receptor)
                block_ip(client_ip)
                abort(400, description="Access denied.")

            if detect_bruteforce_attack(username):
                logging.warning(f"Brute force attack detected for Account: '{username}' from IP: '{client_ip}'")
                send_email(subject="Attack attempt detected from your APP: BruteForce Attack",body=f"Brute force attack detected on your APP for Account: {username} from IP: {client_ip} at {current_time}, be carefull",to=mail_receptor)
                block_ip(client_ip)
                abort(429, description="Too many failed attempts. Please try again later.")

            if detect_sql_injection(username) or detect_sql_injection(password):
                logging.warning(f"SQL injection detected from IP : '{client_ip}'. Account: '{username}', Password: '{password}'")
                send_email(subject="Attack attempt detected from your APP: SQL Injection Attack",body=f"SQL Inject attack detected on your APP for Account: {username} from IP: {client_ip} at {current_time}, be carefull",to=mail_receptor)
                block_ip(client_ip)
                abort(400, description="Malicious input detected.")

            if detect_xss(username) or detect_xss(password):
                logging.warning(f"XSS attack detected from IP: '{client_ip}'. Account: '{username}', Password: '{password}'")
                send_email(subject="Attack attempt detected from your APP: XSS Attack",body=f"XSS attack detected on your APP for Account: {username} from IP: {client_ip} at {current_time}, be carefull",to=mail_receptor)
                block_ip(client_ip)
                abort(400, description="Malicious input detected.")

        return func(*args, **kwargs)
    return wrapper
