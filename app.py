from flask import Flask, render_template, request, redirect, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
import datetime
import subprocess
import os
import pdfkit

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # start_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    parameters = db.Column(db.String(255))
    command = db.Column(db.String(255))
    results = db.Column(db.Text)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip_address = request.form['ip_address']
    subnet_mask = request.form['subnet_mask']
    port_option = request.form['port_option']
    list_scan = request.form.get('list_scan')
    no_port_scan = request.form.get('no_port_scan')
    no_ping = request.form.get('no_ping')
    syn_scan = request.form.get('syn_scan')
    tcp_connect_scan = request.form.get('tcp_connect_scan')
    udp_scan = request.form.get('udp_scan')
    sctp_init_scan = request.form.get('sctp_init_scan')
    ack_scan = request.form.get('ack_scan')
    ip_protocol_scan = request.form.get('ip_protocol_scan')
    aggressive = request.form.get('aggressive')

    port_single = request.form.get('port_single')
    port_range = request.form.get('port_range')

    parameters = '' #parametry polecenia nmap


    if port_option:
        if port_option == 'single':
            parameters += f' -p {port_single}'
        elif port_option == 'range':
            parameters += f' -p {port_range}'
        elif port_option == 'all':
            parameters += f' -p-'
        elif port_option == 'default':
            parameters += ''


    if list_scan:
        parameters += ' -sL'
    if no_port_scan:
        parameters += ' -sn'
    if no_ping:
        parameters += ' -Pn'
    if syn_scan:
        parameters += ' -sS'
    if tcp_connect_scan:
        parameters += ' -sT'
    if udp_scan:
        parameters += ' -sU'
    if sctp_init_scan:
        parameters += ' -sY'
    if ack_scan:
        parameters += ' -sA'
    if ip_protocol_scan:
        parameters += ' -sO'
    if aggressive:
        parameters += ' -A'


    if subnet_mask != '':
        command = f'sudo nmap{parameters} {ip_address}/{subnet_mask}'
    else:
        command = f'sudo nmap{parameters} {ip_address}'




    try:
        start_time = datetime.datetime.utcnow()
        results = subprocess.check_output(command, shell=True).decode('utf-8')
        end_time = datetime.datetime.utcnow()
        new_scan = Scan(parameters=parameters, results=results, command=command, start_time=start_time, end_time=end_time)
        db.session.add(new_scan)
        db.session.commit()
        return redirect('/scans')
    except subprocess.CalledProcessError as e:
        error_message = f'An error occurred: {e.output.decode("utf-8")}'
        return render_template('index.html', error_message=error_message)

@app.route('/scans')
def scans():
    scans = Scan.query.order_by(Scan.start_time.desc()).all()
    return render_template('scans.html', scans=scans)

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    scan = Scan.query.get(scan_id)
    return render_template('scan_details.html', scan=scan)

@app.route('/scan/<int:scan_id>/download')
def download(scan_id):
    # Pobierz skan na podstawie scan_id
    scan = Scan.query.get(scan_id)

    return render_template('download.html', scan=scan)

# @app.route('/scan/<int:scan_id>/download')
@app.route('/download/<int:scan_id>.txt')
def download_txt(scan_id):

    scan = Scan.query.get(scan_id)

    txt_data = scan.results

    txt_file_path = f"scan_{scan_id}.txt"
    with open(txt_file_path, 'w') as txt_file:
        txt_file.write(txt_data)

    return send_file(txt_file_path, as_attachment=True, download_name=f'scan{scan.id}.txt')

@app.route('/download/<int:scan_id>.html')
def download_html(scan_id):
    scan = Scan.query.get(scan_id)

    html_data = scan.results

    html_file_path = f'scan_{scan_id}.html'
    with open(html_file_path, 'w') as html_file:
        #html_file.write(f"<html>\n<head>\n<title>scan{scan_id}\n</title>\n</head>\n \<body style='background-color: black'>\n<h1 style='color: lawngreen>{scan.results}</h1>\n</body>\n</html>")
        html_file.write(f"{scan.results}")

    return send_file(html_file_path, as_attachment=True, download_name=f'scan{scan.id}.html')

@app.route('/download/<int:scan_id>.pdf')
def download_pdf(scan_id):
    scan = Scan.query.get(scan_id)

    html_data = scan.results

    pdf_config = {
        'page-size': 'A4',
        'margin-top': '0mm',
        'margin-bottom': '0mm',
        'margin-right': '0mm',
        'margin-left': '0mm'
    }
    pdf_file = pdfkit.from_string(html_data, False, configuration=pdfkit.configuration(wkhtmltopdf="/usr/bin/wkhtmltopdf"), options=pdf_config)

    response = make_response(pdf_file)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=scan{scan.id}.pdf'
    return response



if __name__ == '__main__':
    app.run(debug=True)
