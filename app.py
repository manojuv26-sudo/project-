from flask import Flask, render_template, request
import numpy as np
import joblib

app = Flask(__name__)

# Load the best model
model = joblib.load('best_dns_model.pkl')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/detect', methods=['GET', 'POST'])
def detect():
    if request.method == 'POST':
        try:
            # Get input values from form
            duration = float(request.form['duration'])
            flow_bytes_sent = float(request.form['flow_bytes_sent'])
            flow_bytes_received = float(request.form['flow_bytes_received'])
            packet_length_mean = float(request.form['packet_length_mean'])
            packet_time_variance = float(request.form['packet_time_variance'])
            response_time_mean = float(request.form['response_time_mean'])

            # Create input array for prediction
            input_data = np.array([[duration, flow_bytes_sent, flow_bytes_received,
                                    packet_length_mean, packet_time_variance, response_time_mean]])

            # Predict using the model
            prediction = model.predict(input_data)[0]
            result = "Malicious DNS Traffic Detected" if prediction == 1 else "Normal DNS Traffic"

            return render_template('result.html', result=result)

        except Exception as e:
            return render_template('result.html', result=f"Error: {str(e)}")

    return render_template('detect.html')

@app.route('/description')
def description():
    return render_template('description.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run()
