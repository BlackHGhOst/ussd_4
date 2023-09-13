import os
import requests
from flask import Flask, request, jsonify
import sqlite3
import json
import hashlib
import uuid
import logging

app = Flask(__name__)
DATABASE_NAME = 'registration.db'

#Log
logging.basicConfig(level=logging.INFO)

# Initialize SQLite database
def init_db():
    try:
        with sqlite3.connect(DATABASE_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS registrations (
                    id INTEGER PRIMARY KEY,
                    user_id TEXT,
                    name TEXT,
                    nrc_number TEXT,
                    num_children INTEGER,
                    health_center TEXT,
                    password TEXT,
                    password_salt TEXT,
                    pin TEXT,
                    children_info TEXT
                )
            ''')
        conn.commit()
    except Exception as e:
        logging.error(f"Error initializing database: {str(e)}")
    finally:
        conn.close()

# Function to hash the password with a salt
def hash_password(password: str) -> tuple:
    salt = uuid.uuid4().hex
    hashed_password = hashlib.sha256(salt.encode() + password.encode()).hexdigest()
    return hashed_password, salt

# Function to hash the pin
def hash_pin(pin: str) -> str:
    return hashlib.md5(pin.encode()).hexdigest()

# Function to insert registration data into the database
def insert_registration(user_id, name, nrc_number, num_children, health_center, password, pin):
    hashed_password, salt = hash_password(password)
    hashed_pin = hash_pin(pin)
    with sqlite3.connect(DATABASE_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO registrations (user_id, name, nrc_number, num_children, health_center, password, password_salt, pin)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, name, nrc_number, num_children, health_center, hashed_password, salt, hashed_pin))

# Function to check if a user is already registered
def is_user_registered(user_id):
    with sqlite3.connect(DATABASE_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM registrations WHERE user_id = ?', (user_id,))
        return cursor.fetchone()[0] > 0

#Saving childs particulars
def save_child_particulars(user_id, child_info):
    with sqlite3.connect(DATABASE_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE registrations SET children_info = ? WHERE user_id = ?', (json.dumps(child_info), user_id))

#Retrieve registered children
def retrieve_existing_children(user_id):
    with sqlite3.connect(DATABASE_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT children_info FROM registrations WHERE user_id = ?', (user_id,))
        return json.loads(cursor.fetchone()[0])

# Password & Pin Functions
def check_pin(user_id, pin):
    with sqlite3.connect(DATABASE_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT pin FROM registrations WHERE user_id = ?', (user_id,))
        stored_pin = cursor.fetchone()[0]
        return stored_pin == hash_pin(pin)


ussd_menu = {
    "1": "Welcome to Health. Press:\n1. Register\n2. Manage Profile\n3. Child Information\n0. Exit.",

    # Registration
    "1*1": "Register:\n1. Name\n2. NRC Number\n3. Number Of Children\n4. Health Centre\n5. Set Password\n0. Go back",
    "1*1*1": "Enter your Name or 0 to go back.",
    "1*1*2": "Enter your NRC Number or 0 to go back.",
    "1*1*3": "Enter the Number Of Children or 0 to go back.",
    "1*1*4": "Enter the Health Centre Registered Under or 0 to go back.",
    "1*1*5": "Enter your desired Password or 0 to go back.",

    # Profile Management
    "1*2": "Manage Profile:\n1. View Profile\n2. Edit Profile\n0. Go back",
    "1*2*1": "Your Profile:\nName: {name}\nNRC Number: {nrc}\nNumber Of Children: {num_children}\nHealth Centre Registered Under: {health_center}\n\n1. Edit Profile\n0. Go back",
    "1*2*2": "Edit Profile:\n1. Name\n2. NRC Number\n3. Number Of Children\n4. Health Centre\n5. Change Password\n0. Go back",

    # Child Information Management
    "1*3": "Child Information:\n1. Register Child\n2. View Existing Children\n0. Go back",
    "1*3*1": "Register Child:\n1. Name\n2. Gender\n3. Date of First Clinic Visit\n4. Date of Birth\n5. Birth Weight\n6. Place of Birth\n0. Go back",
    "1*3*1*1": "Enter Child's Name or 0 to go back.",
    "1*3*1*2": "Enter Child's Gender (Male or Female) or 0 to go back.",
    "1*3*1*3": "Enter Date child was first seen at the clinic (YYYY-MM-DD) or 0 to go back.",
    "1*3*1*4": "Enter Child's Date of Birth (YYYY-MM-DD) or 0 to go back.",
    "1*3*1*5": "Enter Child's Birth Weight (e.g., 3.2kg) or 0 to go back.",
    "1*3*1*6": "Enter Place of Birth or 0 to go back.",
    "1*3*2": "View Existing Children:\n[Dynamic list of registered children with option numbers]\n0. Go back"
}


# Handling USSD callback from Africa's Talking
@app.route('/ussd-callback', methods=['POST'])
def ussd_callback():
    try:
        logging.info(f"received data: {request.data}")

        # Check if the request data is not empty and is JSON
        if not request.data:
            raise ValueError("Empty request body")

        if not request.is_json:
            raise ValueError("Request body is not in JSON format")

        session_id = request.json['sessionId']
        phone_number = request.json['phoneNumber']
        user_input = request.json['text']

#existing check
        response_text = process_ussd_input(user_input, user_session_data) if is_user_registered(session_id) else ussd_menu[
            "1"]
# Ending/continuing session
        prefix = "END" if "Exit" in response_text or "Thank You" in response_text else "CON"

        return jsonify({"sessionId": session_id, "phoneNumber": phone_number, "text": prefix + "" + response_text})


    except Exception as e:
        logging.error(f"Error in ussd_callback: {str(e)}")
        return jsonify({"status": "Error", "message": str(e)}), 500

def process_ussd_input(user_input, user_session_data):
    if user_input == '':
        return ussd_menu['1']

    if "1*1" in user_input:  # Registration paths
        sections = ["Name", "NRC Number", "Number Of Children", "Health Centre", "Set Password"]
        for index, section in enumerate(sections, 1):
            key = f"1*1*{index}"
            if user_input.startswith(key) and len(user_input.split('*')) == 3:
                if section in user_session_data:
                    return f"You've already entered {section}: {user_session_data[section]}. Enter again or 0 to go back."
                return ussd_menu[key]

            if user_input.startswith(key) and len(user_input.split('*')) > 3:
                user_session_data[section] = user_input.split('*')[-1]
                return f"{section} saved! Continue with registration."

# Function to send the USSD response to Africa's Talking's USSD API
def send_ussd_response(response):
    username = 'Neville_Nyati' # Replace with your Africa's Talking username
    api_key = 'd93c30f5702cb0ec8108757042cf59c2a3a9008a89bb213a65a3931fe3022593' # Replace with your Africa's Talking API key
    url = 'https://api.africastalking.com/ussd/send'

    headers = {
        'Content-Type': 'application/json',
        'apiKey': api_key,
    }

    try:
        response = requests.post(url, json=response, headers=headers)
        if response.status_code == 201:
            print("USSD response sent successfully")
        else:
            print("Failed to send USSD response")
    except Exception as e:
        print(f"Error sending USSD response: {str(e)}")

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))