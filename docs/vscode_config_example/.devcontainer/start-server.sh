#!/bin/bash
cd /workspaces/threat-modeling
python -m http.server 8000 --directory build > /tmp/http-server.log 2>&1 &
echo "HTTP server started on port 8000 (PID: $!)"
