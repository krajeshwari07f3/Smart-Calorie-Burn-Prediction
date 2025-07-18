from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
# You'll need password hashing
# Removed password hashing as per user request
# Removed password hashing as per user request
# from werkzeug.security import check_password_hash, generate_password_hash
import pickle
import numpy as np
import pandas as pd
from functools import wraps
app = Flask(__name__)
# IMPORTANT: Use a strong, random secret key and keep it secure
app.secret_key = 'd6f345b25a894e7c8c2a3b7d5f10g12h'  # Replace with a securely generated key
# --- !!! This is a placeholder - Replace with a database !!! ---
# In a real app, load users from a database (e.g., SQLAlchemy)
# Store HASHED passwords, never plain text
users_db = {
    "testuser": {
        "password": "password123"
        # Add other user details if needed
    }
}
# --- End Placeholder ---
# Load the trained model
try:
    with open("best_model.pkl", "rb") as f:
        model = pickle.load(f)
except FileNotFoundError:
    print("Error: best_model.pkl not found. Train the model first.")
    # Handle appropriately - maybe exit or disable prediction
    model = None # Or a dummy model
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url)) # Redirect back after login
        return f(*args, **kwargs)
    return decorated_function
@app.route('/login', methods=['GET', 'POST'])
def login():
    print("Login route accessed, method:", request.method)
    if 'username' in session:
        print("User already logged in:", session['username'])
        return redirect(url_for('home')) # Already logged in
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"Login attempt with username: {username}")
        # Temporary: Accept any username/password without validation to sync with frontend sessionStorage users
        if username and password:
            session['username'] = username
            session.permanent = True # Optional: make session last longer
            print(f"Login successful for user: {username}")
            print("Session contents after login:", dict(session))
            flash(f'Welcome back, {username}!', 'success')
            next_page = request.args.get('next') # For redirecting back after login
            redirect_url = next_page or url_for('home')
            print(f"Redirecting to: {redirect_url}")
            return redirect(redirect_url)
        else:
            # Invalid credentials
            print("Invalid login credentials")
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')
    # For GET request
    return render_template('login.html')
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('signup-username')
    email = request.form.get('signup-email')
    password = request.form.get('signup-password')
    confirm_password = request.form.get('signup-confirm-password')
    # Basic validation
    if not username or not email or not password or not confirm_password:
        flash('Please fill out all fields.', 'danger')
        return render_template('login.html', signup_active=True)
    if password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return render_template('login.html', signup_active=True)
    if username in users_db:
        flash('Username already exists. Please choose a different one.', 'danger')
        return render_template('login.html', signup_active=True)
    # Password strength check (simple example)
    if len(password) < 8:
        flash('Password must be at least 8 characters long.', 'danger')
        return render_template('login.html', signup_active=True)

    # Store the user with plain text password as per user request
    users_db[username] = {
        'password': password,
        'email': email
    }
    flash('Account created successfully! Please login.', 'success')
    return redirect(url_for('login'))
@app.route('/')
@login_required
def home():
    # No need to check session here, decorator handles it
    return render_template('index.html', username=session.get('username'))
@app.route('/predict', methods=['POST'])
@login_required
def predict():
    if not model:
         flash('Prediction model is not available.', 'danger')
         return render_template('index.html', username=session.get('username'))
    try:
        # --- Refined Data Handling ---
        # Check content type for safety
        if request.content_type == 'application/json':
            data = request.get_json()
            if not data:
                 return jsonify({'error': 'Invalid JSON data received'}), 400
            # Explicitly get values, provide defaults, and convert safely
            try:
                features_list = [
                    float(data.get('Gender', 0)),
                    float(data.get('Age', 0)),
                    float(data.get('Height', 0)),
                    float(data.get('Weight', 0)),
                    float(data.get('Duration', 0)),
                    float(data.get('Heart_Rate', 0)),
                    float(data.get('Body_Temp', 0))
                ]
            except (ValueError, TypeError) as e:
                 return jsonify({'error': f'Invalid data type in JSON: {e}'}), 400
        elif request.form:
             # Get values by name for robustness
             try:
                 features_list = [
                     float(request.form.get('Gender', 0)),
                     float(request.form.get('Age', 0)),
                     float(request.form.get('Height', 0)),
                     float(request.form.get('Weight', 0)),
                     float(request.form.get('Duration', 0)),
                     float(request.form.get('Heart_Rate', 0)),
                     float(request.form.get('Body_Temp', 0))
                 ]
             except (ValueError, TypeError) as e:
                 flash(f'Invalid data type submitted in form: {e}', 'danger')
                 return render_template('index.html', username=session.get('username'))
        else:
             flash('Unsupported request format.', 'danger')
             return render_template('index.html', username=session.get('username'))
        # --- End Refined Data Handling ---
        features = np.array(features_list).reshape(1, -1)
        prediction = model.predict(features)[0]
        # Generate weight loss suggestions based on prediction
        suggestions = []
        if prediction > 500:
            suggestions.append("Great job! Keep up the intense workouts.")
            suggestions.append("Ensure you're refueling properly after high-calorie burn sessions.")
        elif prediction > 200:
             suggestions.append("Good effort! Consider slightly increasing duration or intensity next time.")
             suggestions.append("Focus on consistency in your workouts.")
        else:
            suggestions.append("Try to increase your workout duration or intensity for better calorie burn.")
            suggestions.append("Even short bursts of activity throughout the day can help.")
        suggestions.append("Maintain a balanced diet rich in whole foods.")
        suggestions.append("Stay hydrated, especially before, during, and after exercise.")
        suggestions.append("Combine cardio with strength training for optimal results.")
        # If request was JSON, return JSON
        if request.content_type == 'application/json':
            return jsonify({
                'prediction': round(prediction, 2),
                'suggestions': suggestions
            })
        else: # Otherwise, render the template
            return render_template('index.html',
                                   prediction_text=f'Estimated Calories Burnt: {prediction:.2f}',
                                   suggestions=suggestions,
                                   username=session.get('username'))
    except Exception as e:
        print(f"Error during prediction: {e}") # Log the error server-side
        if request.content_type == 'application/json':
             return jsonify({'error': 'An error occurred during prediction.'}), 500
        else:
             flash('An error occurred during prediction. Please try again.', 'danger')
             return render_template('index.html', username=session.get('username'))
if __name__ == '__main__':
    # Set host='0.0.0.0' to make it accessible on your network
    app.run(debug=True, host='0.0.0.0')