#!/usr/bin/env bash
set -e
cd backend
python3 -m venv venv || true
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
