#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from flask import Flask, render_template, request, Blueprint, Response, g
from flask_sspi import authenticate

Blueprint1 = Blueprint('Blueprint1', __name__)
app = Blueprint1

@app.before_request
@authenticate
def before_request():
  pass

@app.route("/")
def test_blueprint():
    print("user: " + g.current_user)
    return render_template('test.html', function = test_blueprint.__name__) # current_user is also defined in Jinja's context
