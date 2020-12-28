#!/usr/bin/env python
DEBUG = False

import sys
sys.path.insert(0, "../")

if DEBUG:
    from flask_sspi_fake import *
else:
    from flask_sspi import *

import logging
logging.basicConfig(level=logging.DEBUG)

import os, socket
import win32net  # install package pypiwin32 
from flask import Flask
from flask import render_template, session, g, url_for

app = Flask(__name__)
app.secret_key = 'efca0226-1746-43f6-92ac-1975e1eea085'

init_sspi(app)


@app.route("/")
def index():
    links = []
    for rule in app.url_map.iter_rules():
        # Filter out rules we can't navigate to in a browser
        # and rules that require parameters
        if "GET" in rule.methods and has_no_empty_params(rule):
            url = url_for(rule.endpoint, **(rule.defaults or {}))
            if rule.endpoint.startswith("test_") or rule.endpoint.startswith("Blue"):
                links.append((url, rule.endpoint))
    # links is now a list of url, endpoint tuples
    return render_template("index.html", links=links)


@app.route("/requires_authentication")
@requires_authentication
def test_requires_authentication(user):
    print("user: " + user)
    return render_template('test.html', current_user=user, function=test_requires_authentication.__name__)


@app.route("/authenticate")
@authenticate
def test_authenticate():
    print("user: " + g.current_user)
    return render_template('test.html', function=test_authenticate.__name__)  # current_user is also defined in Jinja's context


@app.route("/impersonate")
@authenticate
def test_impersonate():
    with Impersonate():  # Some functions like print do not work with this. Hard to debug.
        user = os.getlogin()
    domain = '.'.join(socket.getfqdn().split('.')[1:])
    groups = win32net.NetUserGetGroups(domain, user)
    groups = ', '.join(map(lambda r:r[0], groups))
    print("user: " + os.getlogin())
    return render_template('test_groups.html', current_user=user, groups=groups, function=test_impersonate.__name__)  # current_user is also defined in Jinja's context


def has_no_empty_params(rule):
    defaults = rule.defaults if rule.defaults is not None else ()
    arguments = rule.arguments if rule.arguments is not None else ()
    return len(defaults) >= len(arguments)


########### Registrations ###########
from blueprint1.main import Blueprint1
########### Register apps ###########
app.register_blueprint(Blueprint1, url_prefix='/blueprint1')

if __name__ == '__main__':
    init_sspi(app)
    app.run(host='0.0.0.0')
