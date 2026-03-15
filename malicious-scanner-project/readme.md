# Terminal 1 — Start Flask API
cd /Volumes/X/coding/code/demmisto-internship/malicious-scanner-project
python3 app.py

# Terminal 2 — Start Dashboard
cd /Volumes/X/coding/code/demmisto-internship/malicious-scanner-project
python3 -m http.server 8080

# Terminal 3 — Start n8n (on Ubuntu laptop)
docker start n8n

open http://localhost:8080/dashboard.html
```

Or just type this in Safari/Chrome address bar:
```
http://localhost:8080/dashboard.html