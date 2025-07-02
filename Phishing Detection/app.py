import re #reqular expression
from urllib.parse import urlparse
import pandas as pd
import joblib #read machine learning model
from flask import Flask, request, render_template, redirect, url_for, flash, session #python backend framework
import psycopg2 #connecting database
import plotly.express as px
import plotly.io as pio
from datetime import datetime
import os



# Load the trained model and scaler
model = joblib.load("random_forest_phishing.pkl")
scaler = joblib.load("scaler_phishing.pkl")



def connect_to_db():
    return psycopg2.connect(
        user="postgres",
        password="Joel@123",
        host="localhost",
        port=5432,
        database="phish"
    )

conn = connect_to_db()
cursor = conn.cursor()
# Flask App
app = Flask(__name__)
app.secret_key = "phish"



UPLOAD_FOLDER = "uploads/"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create folder if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Feature Extraction Function
def extract_features(url):
    parsed_url = urlparse(url)
    features = {
        'url_length': len(url),
        'hostname_length': len(parsed_url.netloc),
        'path_length': len(parsed_url.path),
        'fd_length': len(parsed_url.path.split('/')[-1]),
        'count-': url.count('-'),
        'count@': url.count('@'),
        'count?': url.count('?'),
        'count%': url.count('%'),
        'count.': url.count('.'),
        'count=': url.count('='),
        'count-http': url.count('http'),
        'count-https': url.count('https'),
        'count-www': url.count('www'),
        'count-digits': sum(c.isdigit() for c in url),
        'count-letters': sum(c.isalpha() for c in url),
        'count_dir': url.count('/'),
        'use_of_ip': int(bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', parsed_url.netloc))),
        'short_url': int('bit.ly' in url or 'tinyurl' in url or 't.co' in url)
    }
    return features

# Predict Function
def predict_url(url, trained_model, scaler):
    features = extract_features(url)
    feature_df = pd.DataFrame([features])
    scaled_features = scaler.transform(feature_df)
    prediction = trained_model.predict(scaled_features)
    return "Malicious" if prediction[0] == 1 else "Benign"

# Scan file using VirusTotal API






# Save Prediction in Database
def save_prediction(url, prediction):
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO url_predictions (url, prediction, created_at) VALUES (%s, %s, %s)",
            (url, prediction, datetime.now())
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error saving to database: {e}")

@app.route("/")
def login():
    return render_template("login.html")

@app.route('/add_users', methods=['POST'])
def add_users():
    name = request.form.get('uname')
    email = request.form.get('uemail')
    password = request.form.get('upassword')

    cursor.execute("""
        INSERT INTO login(name, email, password)
        VALUES(%s, %s, %s)
    """, (name, email, password))
    conn.commit()

    return render_template("successfull.html")

@app.route('/login_validation', methods=['POST'])
def login_validation():
    email = request.form.get('email')
    password = request.form.get('password')

    cursor.execute("SELECT user_id, name, email FROM login WHERE email = %s AND password = %s", (email, password))
    user = cursor.fetchone()

    if user:
        session['user_id'] = user[0]
        session['user_name'] = user[1]
        session['user_email'] = user[2]
        return redirect('/starter')
    else:
        flash('Invalid email or password', 'danger')
        return redirect('/')

@app.route('/starter')
def starter():
    name = session.get('user_name')
    if name:
        return render_template("index.html", name=name)
    else:
        flash('Please log in first.', 'warning')
        return redirect('/')

@app.route("/predict", methods=["POST"])
def predict():
    if request.method == "POST":
        url = request.form["url"]
        prediction = predict_url(url, model, scaler)
        save_prediction(url, prediction)
        return render_template("index.html", result=prediction, url=url)

@app.route("/history")
def history():
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, url, prediction, created_at FROM url_predictions")
        records = cursor.fetchall()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error fetching from database: {e}")
        records = []

    return render_template("history.html", history=records)


@app.route("/visualize")
def visualize():
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("SELECT prediction, COUNT(*) FROM url_predictions GROUP BY prediction")
        prediction_data = cursor.fetchall()

        cursor.execute("SELECT created_at FROM url_predictions")
        timestamps = [row[0] for row in cursor.fetchall()]

        cursor.close()
        conn.close()

        # Data processing for visualization
        df_pie = pd.DataFrame(prediction_data, columns=["Prediction", "Count"])
        df_line = pd.DataFrame(timestamps, columns=["Timestamp"])
        df_line['Timestamp'] = pd.to_datetime(df_line['Timestamp'])
        df_line['Hour'] = df_line['Timestamp'].dt.hour

        # Generate visualizations
        pie_chart = pio.to_html(px.pie(df_pie, values="Count", names="Prediction", title="Malicious vs Benign URLs"))
        line_chart = pio.to_html(px.histogram(df_line, x="Hour", title="Submission Frequency by Hour"))

    except Exception as e:
        print(f"Error generating visualization: {e}")
        pie_chart = "<p>Error loading visualization.</p>"
        line_chart = "<p>Error loading visualization.</p>"

    return render_template("visualize.html", pie_chart=pie_chart, line_chart=line_chart)

@app.route("/logout")
def logout():
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
