#!/usr/bin/env python

import sys
sys.path.append("../")

import logging
logging.basicConfig(level=logging.DEBUG)

from flask import Flask
from flask import render_template
from flask_sspi import init_sspi
from flask_sspi import requires_authentication

DEBUG=True

app = Flask(__name__)
app.secret_key = 'efca0226-1746-43f6-92ac-1975e1eea085'


@app.route("/")
@requires_authentication
def index(user):
    print("index")
    return render_template('index.html', user=user)


if __name__ == '__main__':
    init_sspi(app)
    app.run(host='0.0.0.0')
