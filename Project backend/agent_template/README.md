# DAVE Monitoring Agent

This agent provides event-based monitoring of all currently accessible Windows drive roots. It does not copy or upload file contents; it sends file-event metadata to the configured DAVE backend.

## First use
1. Pair the PC from the DAVE File Activity page.
2. Download the generated `DAVE-Monitor-Agent.zip`.
3. Extract it.
4. Run `run_agent.bat` once.

## Start / Stop behavior
The agent process can remain open in its PowerShell window. The DAVE File Activity page controls filesystem observation through the backend.

- **Start Monitoring:** the agent activates its Watchdog observers.
- **Stop Monitoring:** the agent stops its Watchdog observers but keeps the Python process and heartbeat/control connection alive. Existing events remain available for review.
- **Ctrl+C:** exits the entire agent process.

## Resource model
- Files are not copied to the backend.
- Filesystem changes are event-driven instead of being polled by repeatedly scanning entire drives.
- A bounded queue prevents unlimited in-memory growth.
- Modified-event debouncing reduces duplicate bursts.

## Local development
Use `http://127.0.0.1:5000` in `config.json` when the Flask backend is running locally.
