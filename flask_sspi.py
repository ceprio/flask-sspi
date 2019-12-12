import sspi, sspicon
import win32api
import base64
import threading

from flask import Response
from flask import _request_ctx_stack as stack
from flask import make_response
from flask import request
from functools import wraps
from socket import gethostname
from os import environ

_SERVICE_NAME = None
_PKG_NAME = 'NTLM'
_sa = sspi.ServerAuth(_PKG_NAME) # should this be per session???
# def print(*args, **kwargs):
    # pass

def init_sspi(app, service='HTTP', hostname=gethostname()):
    '''
    Configure the SSPI service, and validate the presence of the
    appropriate informations if necessary.

    :param app: a flask application
    :type app: flask.Flask
    :param service: GSSAPI service name
    :type service: str
    :param hostname: hostname the service runs under
    :type hostname: str
    '''
    global _SERVICE_NAME
    _SERVICE_NAME = "%s@%s" % (service, hostname)

def _unauthorized(token):
    '''
    Indicate that authentication is required
    
    :param token: token for the next negotiation or None for the first try
    :type token: str
    '''
    return Response('Unauthorized', 401, {'WWW-Authenticate': 'NTLM' if not token else token}, mimetype='text/html') # this can also be Negotiate but does not work on my server

def _forbidden():
    '''
    Indicate a complete authentication failure
    '''
    return Response('Forbidden', 403)

def _get_user_name():
     try:
         return win32api.GetUserName()
     except win32api.error as details:
         # Seeing 'access denied' errors here for non-local users (presumably
         # without permission to login locally).  Get the fully-qualified
         # username, although a side-effect of these permission-denied errors
         # is a lack of Python codecs - so printing the Unicode value fails.
         # So just return the repr(), and avoid codecs completely.
         return repr(win32api.GetUserNameEx(win32api.NameSamCompatible))
         
def _sspi_authenticate(token):
    '''
    Performs GSSAPI Negotiate Authentication

    On success also stashes the server response token for mutual authentication
    at the top of request context with the name sspi_token, along with the
    authenticated user principal with the name sspi_user.

    @param token: Authentication Token
    @type token: str
    @returns sspi return code or None on failure and token
    @rtype: str or None
    '''
    ctx = stack.top

    if token.startswith(_PKG_NAME):
        recv_token_encoded = ''.join(token.split()[1:])
        recv_token = base64.b64decode(recv_token_encoded)
        print(recv_token)
        try:
            error_code, token = _sa.authorize(recv_token)
        except sspi.error as details:
            print(f"sspi.error: {details}")
            return None, None
        token = token[0].Buffer
        if token:
            token = f"{_PKG_NAME} {base64.b64encode(token).decode('utf-8')}"
        if error_code == sspicon.SECPKG_NEGOTIATION_COMPLETE:
            _sa.ctxt.ImpersonateSecurityContext()
            ctx.sspi_user=_get_user_name()
            _sa.ctxt.RevertSecurityContext()
        return error_code, token
    raise Exception("Wrong authentication mode")

def requires_authentication(function):
    '''
    Require that the wrapped view function only be called by users
    authenticated with SSPI. The view function will have the authenticated
    users principal passed to it as its first argument.

    :param function: flask view function
    :type function: function
    :returns: decorated function
    :rtype: function
    '''
    @wraps(function)
    def decorated(*args, **kwargs):
        print("decorated")
        recv_token_encoded = request.headers.get("Authorization")
        token_encoded = None
        if recv_token_encoded:
            ctx = stack.top
            print(f"recv:{recv_token_encoded}")
            rc, token_encoded = _sspi_authenticate(recv_token_encoded)
            print(f"send:{token_encoded}")
            print(f"error_code: {rc}")
            if rc == sspicon.SECPKG_NEGOTIATION_COMPLETE:
                print("complete")
                response = function(ctx.sspi_user, *args, **kwargs)
                response = make_response(response)
                # if token is not None:
                    # print("with token")
                    # response.headers['WWW-Authenticate'] = token_encoded
                return response # passes here a few times while negotiating
            elif rc not in (sspicon.SEC_I_CONTINUE_NEEDED, sspicon.SEC_I_COMPLETE_NEEDED,sspicon.SEC_I_COMPLETE_AND_CONTINUE):
                return _forbidden()
        print(f"_unauthorized({token_encoded})")
        return _unauthorized(token_encoded) 
    return decorated
