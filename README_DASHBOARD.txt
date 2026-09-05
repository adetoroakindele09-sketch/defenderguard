DAVE PROJECT - LIVE DASHBOARD

IMPORTANT:
Use the Project backend folder to start Flask.

1. Open: DAVE PROJECT/Project backend
2. Create a new venv on each laptop:
   py -m venv venv
3. Activate:
   venv\Scripts\activate
4. Install:
   python -m pip install -r requirements.txt
5. Start:
   py app.py
6. Open the dashboard from:
   DAVE PROJECT/Project/dashboard.html

The dashboard calls http://127.0.0.1:5000/dashboard/stats every 2 seconds.
If you still see an old chart placeholder, use Ctrl+F5 or close the old dashboard tab and open the dashboard.html from THIS ZIP.

Note: Total Files is a count of scan/activity records, not a recursive count of every file on the computer.
