import sspi, sspicon
import win32api
import base64
import logging
logger = logging.getLogger(__name__)

from flask import Response
from flask import _request_ctx_stack as stack
from flask import make_response
from flask import request, session
from functools import wraps
from socket import gethostname
from os import environ
import datetime
import uuid

_SERVICE_NAME = None
_PKG_NAME = 'NTLM'
_sessions = {}

def init_sspi(app, service='HTTP', hostname=gethostname(), package='NTLM'):
    '''
    Configure the SSPI service, and validate the presence of the
    appropriate informations if necessary.

    :param app: a flask application
    :type app: flask.Flask
    :param service: GSSAPI service name
    :type service: str
    :param hostname: hostname the service runs under
    :type hostname: str
    :param package: package the service runs under ('NTLM') ('Negotiate' is not yet implemented)
    :type package: str
    '''
    global _SERVICE_NAME
    _SERVICE_NAME = "%s@%s" % (service, hostname)
    _PKG_NAME = package

def _unauthorized(token):
    '''
    Indicate that authentication is required
    
    :param token: token for the next negotiation or None for the first try
    :type token: str
    '''
    if not token:
        return Response('Unauthorized', 401, {'WWW-Authenticate': 'NTLM', 'server':'Microsoft-IIS/8.5'}, mimetype='text/html') # this can also be Negotiate but does not work on my server
    else:
        return Response('Unauthorized', 401, {'WWW-Authenticate': token, 'server':'Microsoft-HTTPAPI/2.0'}, mimetype='text/html') # this can also be Negotiate but does not work on my server

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
    if token.startswith(_PKG_NAME):
        recv_token_encoded = ''.join(token.split()[1:])
        recv_token = base64.b64decode(recv_token_encoded)
        _sa = _sessions[session['uuid']]['sa']
        try:
            error_code, token = _sa.authorize(recv_token)
        except sspi.error as details:
            logger.debug(f"sspi.error: {details}")
            #  TODO: Close _sa?
            del  _sessions[session['uuid']]
            return None, None
        token = token[0].Buffer
        if token:
            token = f"{_PKG_NAME} {base64.b64encode(token).decode('utf-8')}"
        if error_code == sspicon.SECPKG_NEGOTIATION_COMPLETE:
            _sa.ctxt.ImpersonateSecurityContext()
            _sessions[session['uuid']]['username'] = _get_user_name()
            _sessions[session['uuid']]['last_access'] =  datetime.datetime.now()
            _sa.ctxt.RevertSecurityContext()
        return error_code, token
    raise Exception("Wrong authentication mode")

def _init_session():
    logger.debug("Init session")
    session['uuid'] = uuid.uuid4().bytes
    _sessions[session['uuid']] = {}
    _sessions[session['uuid']]['sa'] = sspi.ServerAuth(_PKG_NAME) # one per session
    # TODO cleanup other entries

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
        if 'uuid' not in session or session['uuid'] not in _sessions:
            _init_session()
        if 'username' in _sessions[session['uuid']]:
            if 30*60 < (datetime.datetime.now()-_sessions[session['uuid']]['last_access']).seconds:
                logger.debug('timed out.')
                del _sessions[session['uuid']]
                _init_session()
            else:
                logger.debug('Already authenticated')  
                _sessions[session['uuid']]['last_access'] = datetime.datetime.now()
                response = function(_sessions[session['uuid']]['username'], *args, **kwargs)
                response = make_response(response)
                return response 
        token_encoded = None
        recv_token_encoded = request.headers.get("Authorization")
        if recv_token_encoded:
            logger.debug(f"recv:{recv_token_encoded}")
            rc, token_encoded = _sspi_authenticate(recv_token_encoded)
            if rc == sspicon.SECPKG_NEGOTIATION_COMPLETE:
                logger.debug("Negotiation complete")
                response = function(_sessions[session['uuid']]['username'], *args, **kwargs)
                response = make_response(response)
                return response 
            elif rc not in (sspicon.SEC_I_CONTINUE_NEEDED, sspicon.SEC_I_COMPLETE_NEEDED,sspicon.SEC_I_COMPLETE_AND_CONTINUE):
                logger.debug(f"Forbiden rc={rc}")
                return _forbidden()
        logger.debug(f"Unauthorized yet, continue: {token_encoded}")
        return _unauthorized(token_encoded) # token is None on fist pass
    return decorated
