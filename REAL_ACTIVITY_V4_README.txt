REAL FILE ACTIVITY MONITOR - V4

This version finishes the File Activity page using real Watchdog events.

RUN
1. Open: Project backend
2. Activate venv:
   venv\Scripts\activate
3. Install/update packages:
   python -m pip install -r requirements.txt
4. Start Flask:
   py app.py
5. Open Project/activity.html
6. Click Start Monitoring and enter a real folder path, e.g.
   C:\Users\<your-name>\Documents

TEST SAFELY
Create, edit/save, rename, and delete a harmless text file in the monitored folder.
The page should show those real events within about one second.

IMPORTANT
- No sample/random files or random statuses are generated.
- Process identification is best-effort. Windows may return Unknown because of permissions.
- The 10-second behavioural score is a transparent heuristic, not an ML probability.
- Watchdog file notifications do not expose ordinary read events. The displayed read/write ratio is therefore explicitly labelled as a Create/Write proxy.
- CSV and PDF export the CURRENT live monitoring session, not stale database/demo rows.
