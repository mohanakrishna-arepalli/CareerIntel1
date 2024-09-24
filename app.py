import os
from flask import Flask, render_template, redirect, url_for, session, request, flash
import firebase_admin
from firebase_admin import credentials, auth
import requests
from firebase_admin import exceptions
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Get secret key from .env

cred = credentials.Certificate("firebaseConfig.json")
firebase_admin.initialize_app(cred)

firebase_web_api_key = os.getenv('FIREBASE_API_KEY')

@app.route('/')
def index():
    if 'user' in session:
        return render_template('index.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        login_url = f'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={firebase_web_api_key}'
        login_payload = {
            'email': email,
            'password': password,
            'returnSecureToken': True
        }

        response = requests.post(login_url, json=login_payload)
        response_data = response.json()

        if response.status_code == 200:
            session['user'] = response_data['localId']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            error_message = response_data.get('error', {}).get('message', 'Unknown error')
            flash(f'Error: {error_message}', 'error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            user = auth.create_user(email=email, password=password)
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            error_message = str(e)
            if 'EMAIL_EXISTS' in error_message:
                flash('Email already exists.', 'error')
            elif 'WEAK_PASSWORD' in error_message:
                flash('Password is too weak.', 'error')
            else:
                flash(f'Error creating user: {error_message}', 'error')
            return redirect(url_for('signup'))
    else:
        return render_template('signup.html')


@app.route('/create_account', methods=['POST'])
def create_account():
    email = request.form['email']
    password = request.form['password']

    try:
        user = auth.create_user(email=email, password=password)
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    except exceptions.FirebaseError as e:
        error_message = str(e)
        if 'EMAIL_EXISTS' in error_message:
            flash('Email already exists.', 'error')
        elif 'WEAK_PASSWORD' in error_message:
            flash('Password is too weak.', 'error')
        else:
            flash(f'Error creating user: {error_message}', 'error')
        return redirect(url_for('signup'))
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/companies')
def companies():
    return render_template('companies.html')

@app.route('/resume')
def resume():
    return render_template('resume.html')

@app.route('/communities')
def communities():
    return render_template('communities.html')

@app.route('/chilling.html')
def chilling():
    return render_template('chilling.html')

@app.route('/projects.html')
def projects():
    return render_template('projects.html')

@app.route('/seniors.html')
def seniors():
    return render_template('seniors.html')

@app.route('/off_campus')
def off_campus():
    return render_template('off_campus.html')

# Add routes for each company's specific details page
@app.route('/deloitte.html')
def deloitte():
    return render_template('deloitte.html')

@app.route('/ibm.html')
def ibm():
    return render_template('ibm.html')

@app.route('/tata_elxsi')
def tata_elxsi():
    return render_template('tata_elxsi.html')

@app.route('/synchronyp3')
def synchronyp3():
    return render_template('synchronyp3.html')

@app.route('/micron.html')
def micron():
    return render_template('micron.html')

@app.route('/accenture')
def accenture():
    return render_template('accenture.html')

@app.route('/pwc')
def pwc():
    return render_template('pwc.html')

if __name__ == '__main__':
    app.run(debug=True)
