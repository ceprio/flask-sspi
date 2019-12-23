Flask-SSPI
==========

Flask-SSPI is an extension to `Flask`_ that allows you to trivially add
`NTLM`_ based authentication to your website. It depends on both Flask and
`sspi`_. You can install the requirements from PyPI with
`easy_install` or `pip` or download them by hand.

The official copy of this documentation is available at `Read the Docs`_.

Installation
------------

Install the extension with one of the following commands::

    $ easy_install Flask-SSPI

or alternatively if you have `pip` installed::

    $ pip install Flask-SSPI


Limitations
-----------

Only tested on Chrome. 

For some reason Explorer does not recognise the second `NTLM`_ token that 
is sent by the server and stops negotiations and shows the unauthorized page to the client.
Feel free to submit corrections.

Only `NTLM`_ authentication as been implemented, 'Negotiate' (`Kerberos`_) as not been implemented. 
Any help on this would be appreciated.


How to Use
----------

You can decorate any view functions you wish to require authentication, and changing them to 
accept the authenticated user principal as their first argument::

    from flask-sspi import requires_authentication

    @app.route("/protected/<path:path>")
    @requires_authentication
    def protected_view(user, path):
        ...

Flask-SSPI assumes that the service will be running using the hostname of
the host on which the application is run. If this is not the case, you can
override it by initializing the module::

    from flask-sspi import init_sspi

    init_sspi(app, hostname='example.com', package='Negotiate')

This is not needed if using the 'NTLM' package.

How it works
------------

When a protected view is accessed by a client, it will check to see if the
request includes authentication credentials in an `Authorization` header. If
there are no such credentials, the application will respond immediately with a
`401 Unauthorized` response which includes a `WWW-Authenticate` header field
with a value of `NTLM` indicating to the client that they are currently
unauthorized, but that they can authenticate using Negotiate authentication.

If credentials are presented in the `Authorization` header, the credentials will
be validated, the principal of the authenticating user will be extracted, and
the protected view will be called with the extracted principal passed in as the
first argument.

Once the protected view returns, a `WWW-Authenticate` header will be added to
the response which can then be used by the client to authenticate the server.
This is known as mutual authentication.

SSPI also has the ability to serve the value `Negotiate` from the `WWW-Authenticate` 
header. This as not been implemented but could be in the future with the help of the 
community.

Full Example
------------

To see a simple example, you can download the code `from github
<http://github.com/ceprio/flask-sspi>`_. It is in the example directory.

Changes
-------

0.1
```

-     initial implementation


API References
--------------

The full API reference:


.. automodule:: flask-sspi
   :members:

.. _Flask: http://flask.pocoo.org/
.. _NTLM: https://en.wikipedia.org/wiki/NT_LAN_Manager
.. _sspi: https://en.wikipedia.org/wiki/Security_Support_Provider_Interface_(protocol)
.. _Kerberos: http://wikipedia.org/wiki/Kerberos_(protocol)
.. _pywin32: https://pypi.org/project/pywin32/
.. _flow in sspi: https://blogs.technet.microsoft.com/mist/2018/02/14/windows-authentication-http-request-flow-in-iis/
.. _Read the Docs: https://flask-sspi.readthedocs.org/