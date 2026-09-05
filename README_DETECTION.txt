Detection page update

The Detection page now reads only real scan records created during the current Flask session.
It no longer generates random filenames, predictions, confidence values, hashes, entropy, or timestamps.

Run from Project backend:
  venv\Scripts\activate
  python -m pip install -r requirements.txt
  py app.py

Then open Project\detection.html.
Run a scan from scan.html. The real result will appear on Detection automatically.

CSV: http://127.0.0.1:5000/detection/export.csv
PDF: selected scan -> Export PDF

Note: the current scan engine is a transparent static/behavioural analyzer, not a validated ML model. Do not present the unvalidated accuracy as a measured model accuracy.
