from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime

from feature_extraction import extract_features

scan = Blueprint('scan', __name__)
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DATABASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database.db')


def db():
    return sqlite3.connect(DATABASE)


@scan.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify(success=False, message='No file selected.'), 400
    file = request.files['file']
    if not file.filename:
        return jsonify(success=False, message='Please choose a file.'), 400

    filename = secure_filename(file.filename)
    if not filename:
        return jsonify(success=False, message='Invalid filename.'), 400

    # Associate every scan with the logged-in account.
    # The frontend sends the user's email; this prevents scans from one
    # account appearing on another user's dashboard.
    data_email = (request.form.get('email') or request.args.get('email') or '').strip().lower()
    user_id_raw = (request.form.get('user_id') or request.args.get('user_id') or '').strip()

    conn = db()
    conn.row_factory = sqlite3.Row
    user = None
    if user_id_raw.isdigit():
        user = conn.execute('SELECT id, email FROM users WHERE id=?', (int(user_id_raw),)).fetchone()
    if not user and data_email:
        user = conn.execute('SELECT id, email FROM users WHERE LOWER(email)=?', (data_email,)).fetchone()
    if not user:
        conn.close()
        return jsonify(success=False, message='Valid logged-in user account is required for a scan.'), 401

    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    result = extract_features(filepath)

    cur = conn.cursor()
    cur.execute('''
        INSERT INTO scan_history
        (user_id, file_name, file_path, file_size, prediction, confidence, threat_level,
         write_count, delete_count, create_count, rename_count, write_entropy,
         ext_diversity, sensitive_path_access, read_write_ratio, hidden_file_activity,
         execution_attempts, detection_score, detection_reasons)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        user['id'], filename, filepath, result['file_size'], result['prediction'],
        result['confidence'], result['risk'], result['write_count'], result['delete_count'],
        result['create_count'], result['rename_count'], result['write_entropy'],
        result['ext_diversity'], result['sensitive_path_access'], result['read_write_ratio'],
        result['hidden_file_activity'], result['execution_attempts'], result['score'],
        '; '.join(result['reasons'])
    ))
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()

    return jsonify(success=True, scan_id=scan_id, **result)


@scan.route('/report/<int:scan_id>/pdf', methods=['GET'])
def report_pdf(scan_id):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        return jsonify(success=False, message='reportlab is not installed. Run: python -m pip install reportlab'), 500

    conn = db()
    email = (request.args.get('email') or '').strip().lower()
    user = conn.execute('SELECT id FROM users WHERE LOWER(email)=?', (email,)).fetchone() if email else None
    if not user:
        conn.close()
        return jsonify(success=False, message='User account not found.'), 404
    cur = conn.cursor()
    cur.execute('''SELECT id,file_name,file_size,prediction,confidence,threat_level,scan_time,
                   write_count,delete_count,create_count,rename_count,write_entropy,ext_diversity,
                   sensitive_path_access,read_write_ratio,hidden_file_activity,execution_attempts,
                   detection_score,detection_reasons FROM scan_history WHERE id=? AND user_id=?''', (scan_id, user['id']))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify(success=False, message='Scan not found.'), 404

    out = os.path.join(UPLOAD_FOLDER, f'malware_scan_report_{scan_id}.pdf')
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    story = [Paragraph('Malware Detection Scan Report', styles['Title']), Spacer(1, 12)]
    story.append(Paragraph('Malware Detection Using File Activity', styles['Heading2']))
    story.append(Spacer(1, 8))

    labels = ['Scan ID','File Name','File Size (bytes)','Prediction','Confidence','Risk','Scan Time',
              'Write Count','Delete Count','Create Count','Rename Count','Write Entropy',
              'Extension Diversity','Sensitive Path Access','Read/Write Ratio','Hidden File Activity',
              'Execution Attempts','Detection Score']
    vals = list(row[:18])
    data = [['Metric','Result']] + [[str(a), str(b)] for a,b in zip(labels, vals)]
    table = Table(data, colWidths=[210, 270])
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#163b6d')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.grey),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('PADDING',(0,0),(-1,-1),6),
    ]))
    story.append(table)
    story.append(Spacer(1, 14))
    story.append(Paragraph('<b>Detection explanation:</b> ' + str(row[18]), styles['BodyText']))
    story.append(Spacer(1, 10))
    story.append(Paragraph('Note: This upload scan uses static file analysis. Activity counters represent the controlled scan/upload transaction; they are not a substitute for process-attributed live monitoring.', styles['BodyText']))
    doc.build(story)
    return send_file(out, as_attachment=True, download_name=os.path.basename(out), mimetype='application/pdf')
