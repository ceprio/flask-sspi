# Flask-SSPI

Flask-SSPI is an extension to [Flask](http://flask.pocoo.org/) that allows you to trivially add [NTLM](https://en.wikipedia.org/wiki/NT_LAN_Manager) based authentication to your website. It depends on both Flask and [sspi](https://en.wikipedia.org/wiki/Security_Support_Provider_Interface_(protocol)). You can install the requirements from PyPI with `pip` or `conda`, or download them by hand.

The official copy of this documentation is available at [Read the Docs](https://flask-sspi.readthedocs.org/).

## Installation

Install the extension with one of the following commands:

```sh
pip install Flask-SSPI
```

or using `conda`:

```sh
conda install -c conda-forge flask-sspi
```

## Limitations

- Based on win32 so only works on Windows servers.
- Tested with Chrome and Edge browsers.
- Only [NTLM](https://en.wikipedia.org/wiki/NT_LAN_Manager) authentication has been implemented, 'Negotiate' ([Kerberos](http://wikipedia.org/wiki/Kerberos_(protocol))) has not been implemented.

## How to Use

### First Form (preferred)

You can decorate any view functions you wish to require authentication with the `@authenticate` decorator. To get the current user you can use `g.current_user`:

```python
from flask_sspi import authenticate
from flask import g

@app.route("/protected/<path:path>")
@authenticate
def protected_view(path):
    print(g.current_user)
    ...
```

### Second Form

You can decorate any view functions you wish to require authentication with `@requires_authentication`. With this keyword, you need to change them to accept the authenticated user principal as their first argument:

```python
from flask_sspi import requires_authentication

@app.route("/protected/<path:path>")
@requires_authentication
def protected_view(user, path):
    ...
```

Flask-SSPI assumes that the service will be running using the hostname of the host on which the application is run. If this is not the case, you can override it by initializing the module:

```python
from flask_sspi import init_sspi

init_sspi(app, hostname='example.com', package='NTLM')
```

**NOTE:** `init_sspi` is optional. If used, `current_user` will be defined within the context of Jinja templates. You can then use:

```html
<h1>Hello {{ current_user }}</h1>
```

## How it works

When a protected view is accessed by a client, it will check to see if the request includes authentication credentials in an `Authorization` header. If there are no such credentials, the application will respond immediately with a `401 Unauthorized` response which includes a `WWW-Authenticate` header field with a value of `NTLM` indicating to the client that they are currently unauthorized, but that they can authenticate using Negotiate authentication.

If credentials are presented in the `Authorization` header, the credentials will be validated, the principal of the authenticating user will be extracted, and the protected view will be called with the extracted principal passed in as the first argument.

Once the protected view returns, a `WWW-Authenticate` header will be added to the response which can then be used by the client to authenticate the server. This is known as mutual authentication.

SSPI also has the ability to serve the value `Negotiate` from the `WWW-Authenticate` header. This has not been implemented but could be in the future with the help of the community.

## Full Example

To see a simple example, you can download the code [from github](http://github.com/ceprio/flask-sspi). It is in the example directory.

## Decorators that can be used

| Decorator                  | Description |
|----------------------------|-------------|
| `@authenticate`            | The user must have been identified. |
| `Impersonate`              | Context class to impersonate the connecting user: The user's credentials will be used to execute the route function. Use this to access a database under the user's name per example. **Important:** I could not get this to work with an external database as it requires a trusted connection between the web server and the SQL database (which I don't have). It should work with a database located on the same computer. |
| `@requires_authentication` | Same as login_required but the `user` parameter needs to be specified in the arguments of the route function. **user** will contain the name of the logged user. Kept for backward compatibility. |

For all `flask_sspi` decorators, a `g.current_user` entry is created and accessible within the route function. Within HTML templates the variable `current_user` is also defined if `init_sspi` is used.

## Using before_request function for Blueprints

If you want to restrict access to a whole Blueprint, better to do it with the `before_request` function. Here is an example:

```python
@blueprint.before_request
@authenticate
def before_request():
    pass
```

## Offsite debugging

You may want to test your `flask` application offsite in a non-domain environment. To allow testing without error from `flask_sspi` you can issue `import flask_sspi_fake` before any reference to `flask_sspi`. `flask_sspi_fake` will use stubs instead of the real functions and allow the site to be tested under the credentials of the currently logged user.

## Changes

### 0.1

- Initial implementation

### 0.2

- Added the authenticate decorator and the Impersonate context.

## API References

The full API reference:

See the [API documentation](https://flask-sspi.readthedocs.org/).

---

[Flask]: http://flask.pocoo.org/
[NTLM]: https://en.wikipedia.org/wiki/NT_LAN_Manager
[sspi]: https://en.wikipedia.org/wiki/Security_Support_Provider_Interface_(protocol)
[Kerberos]: http://wikipedia.org/wiki/Kerberos_(protocol)
[pywin32]: https://pypi.org/project/pywin32/
[flow in sspi]: https://blogs.technet.microsoft.com/mist/2018/02/14/windows-authentication-http-request-flow-in-iis/
[Read the Docs]: https://flask-