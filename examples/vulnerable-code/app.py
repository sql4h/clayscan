# INTENTIONALLY VULNERABLE sample — for demonstrating ClayScan's SAST.
import os
import pickle
import hashlib
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/run")
def run():
    # command injection
    return os.system("nslookup " + request.args.get("host"))

@app.route("/user")
def user():
    # SQL injection via string formatting
    cur.execute("SELECT * FROM users WHERE id = %s" % request.args.get("id"))
    return "ok"

@app.route("/load")
def load():
    # unsafe deserialization
    return pickle.loads(request.data)

@app.route("/hello")
def hello():
    # server-side template injection
    return render_template_string("Hello " + request.args.get("name"))

digest = hashlib.md5(b"pw").hexdigest()   # weak hash

if __name__ == "__main__":
    app.run(debug=True)   # debug mode in production
