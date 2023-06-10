# from flask import Flask, render_template, request, redirect, url_for
# import datetime
# import nmap
# import sqlite3
# from docx import Document
# import pdfkit
#
# app = Flask(__name__)
from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
import datetime
import subprocess

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
db = SQLAlchemy(app)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    end_time = db.Column(db.DateTime)
    parameters = db.Column(db.String(255))
    results = db.Column(db.Text)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip_address = request.form['ip_address']
    subnet_mask = request.form['subnet_mask']
    port_range = request.form['port_range']
    host_discovery = request.form.get('host_discovery')
    port_scanning = request.form.get('port_scanning')
    service_detection = request.form.get('service_detection')

    parameters = f'-Pn' if host_discovery else ''
    parameters += f' -p {port_range}' if port_range else ''
    parameters += ' -sV' if service_detection else ''
    parameters += f' {ip_address}/{subnet_mask}' if ip_address and subnet_mask else ip_address

    if validate_parameters(parameters):
        command = f'nmap {parameters}'
        try:
            results = subprocess.check_output(command, shell=True).decode('utf-8')
            new_scan = Scan(parameters=parameters, results=results)
            db.session.add(new_scan)
            db.session.commit()
            return redirect('/scans')
        except subprocess.CalledProcessError as e:
            error_message = f'An error occurred: {e.output.decode("utf-8")}'
            return render_template('index.html', error_message=error_message)
    else:
        error_message = 'Invalid parameters'
        return render_template('index.html', error_message=error_message)

@app.route('/scans')
def scans():
    scans = Scan.query.order_by(Scan.start_time.desc()).all()
    return render_template('scans.html', scans=scans)

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    scan = Scan.query.get(scan_id)
    return render_template('scan_details.html', scan=scan)

def validate_parameters(parameters):
    # Dodaj logikę do walidacji parametrów nmap, zwracając True, jeśli są poprawne, w przeciwnym razie False
    return True



if __name__ == '__main__':
    app.run(debug=True)
