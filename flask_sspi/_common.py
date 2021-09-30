import sspi, sspicon
import win32api
import base64
import logging
logger = logging.getLogger(__name__)

from flask import Response
from flask import _request_ctx_stack as stack
from flask import make_response
from flask import request, session, g
import threading
from functools import wraps
from socket import gethostname
import os
import datetime
from uuid import uuid4

_PKG_NAME = 'NTLM'  # OR 'Negotiate' in future implementations (for kerberos)
_sessions = {}  # There is going to be one _sessions per process 
_sessions_lock = threading.Lock()  # each process may have threads
# time before a user needs to be re-authenticated
_session_duration = 30  # in minutes, don't change dynamically


def _user_context_processor():
    if hasattr(g, "current_user") and g.current_user is not None:
        return dict(current_user=g.current_user)
    else:
        return {}


def init_sspi(app, service='HTTP', hostname=gethostname(), package='NTLM', add_context_processor=True, session_duration=None):
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
    :param add_context_processor: Adds a context processor that find the current_user name from flask g variable content
    :type add_context_processor: bool
    :param session_duration: in minutes, time before a user needs to be re-authenticated
    :type session_duration: int
    '''
    global _SERVICE_NAME
    _SERVICE_NAME = "%s@%s" % (service, hostname)
    _PKG_NAME = package

    if session_duration:
        _session_duration = session_duration

    if add_context_processor:
        app.context_processor(_user_context_processor)


def _unauthorized(token):
    '''
    Indicate that authentication is required
    
    :param token: token for the next negotiation or None for the first try
    :type token: str
    '''
    if not token:
        return Response('Unauthorized', 401, {'WWW-Authenticate': 'NTLM', 'server':'Microsoft-IIS/8.5'}, mimetype='text/html')  # this can also be Negotiate but does not work on my server
    else:
        return Response('Unauthorized', 401, {'WWW-Authenticate': token, 'server':'Microsoft-HTTPAPI/2.0'}, mimetype='text/html')  # this can also be Negotiate but does not work on my server


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
    global _sessions, _sessions_lock
    uuid = session['uuid']
    if token.startswith(_PKG_NAME):
        recv_token_encoded = ''.join(token.split()[1:])
        recv_token = base64.b64decode(recv_token_encoded)
        with _sessions_lock:
            _sa = _sessions[uuid]['sa']
            lock = _sessions[uuid]['lock']
            lock.acquire()
        try:
            error_code, token = _sa.authorize(recv_token)
        except sspi.error as details:
            logger.debug(f"sspi.error: {details}")
            #  TODO: Close _sa?
            with _sessions_lock:
                del  _sessions[uuid]
            return None, None
        finally:
            lock.release()
        token = token[0].Buffer
        if token:
            token = f"{_PKG_NAME} {base64.b64encode(token).decode('utf-8')}"
        return error_code, token  # standard exit; different error codes for different stages
    raise Exception("Wrong authentication mode")

def cleanup_sessions():
    # cleanup other entries according to 'last_access'
    global _sessions, _sessions_lock
    with _sessions_lock:
        del_sessions = []
        for key, d in _sessions.items():
            if d['lock'].locked():
                continue
            if _session_duration * 60 < (datetime.datetime.now() - d['last_access']).seconds:
                del_sessions.append(key)
        for key in del_sessions:
            del _sessions[key]

def _init_session():
    global _sessions, _sessions_lock
    logger.debug("Init session")
    if 'uuid' not in session:
        session['uuid'] = uuid = uuid4().bytes  # init uuid on client
    else:
        uuid = session['uuid']
    with _sessions_lock:
        if uuid not in _sessions:  # make sure
            _sessions[uuid] = {
                'sa': sspi.ServerAuth(_PKG_NAME),
                'lock': threading.Lock(),
                'last_access': datetime.datetime.now(),
                }
    cleanup_sessions()

def _sspi_handler(session):
    global _sessions, _sessions_lock
    if 'uuid' not in session or session['uuid'] not in _sessions:
        _init_session()
    uuid = session['uuid']
    if 'username' in _sessions[uuid]:  # 'username' is used to know if sspi authorized
        if _session_duration * 60 < (datetime.datetime.now() - _sessions[uuid]['last_access']).seconds:
            logger.debug('timed out.')
            with _sessions_lock:
                if uuid in _sessions:  # make sure
                    del _sessions[uuid]
            _init_session()
        else:
            logger.debug('Already authenticated')
            with _sessions[uuid]['lock']:
                _sessions[uuid]['last_access'] = datetime.datetime.now()
            return None
    token_encoded = None
    recv_token_encoded = request.headers.get("Authorization")
    if recv_token_encoded:
        logger.debug(f"recv:{recv_token_encoded}")
        rc, token_encoded = _sspi_authenticate(recv_token_encoded)
        if rc == sspicon.SECPKG_NEGOTIATION_COMPLETE:
            logger.debug("Negotiation complete")
            return None
        elif rc not in (sspicon.SEC_I_CONTINUE_NEEDED, sspicon.SEC_I_COMPLETE_NEEDED, sspicon.SEC_I_COMPLETE_AND_CONTINUE):
            logger.debug(f"Forbiden rc={rc}")
            return _forbidden()
    logger.debug(f"Unauthorized yet, continue: {token_encoded}")
    return _unauthorized(token_encoded)  # token is None on fist pass


class Impersonate():
    '''
    Class that creates a context for the impersonalisation of the client user. 
    May be used to get his name or group appartenance. Could also be used
    to make trusted connections with databases (not tested).
    
    Preferred usage:
        with Impersonate():
            ...
    '''
    def __init__(self, _session=None):
        """ If _session is passed as argument IT MUST BE LOCKED.
        This allows the use of Impersonate within a locked session context.
        """
        self._session = _session

    def open(self):
        '''
        Start of the impersonalisation
        '''
        global _sessions, _sessions_lock
        if not self._session:
            uuid = session['uuid']
            with _sessions_lock:
                _sessions[uuid]['lock'].acquire() # make sure to unlock
                self.lock = _sessions[uuid]['lock']
                self._sa = _sessions[uuid]['sa']
        else:
            self._sa = self._session['sa']
        self._sa.ctxt.ImpersonateSecurityContext()

    def close(self):
        '''
        End of the impersonalisation
        '''
        if self._sa:
            self._sa.ctxt.RevertSecurityContext()
            self._sa = None
            if not self._session:
                self.lock.release()

    def __del__(self):
        if self._sa:
            self.close()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type, value, tb):
        self.close()


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
    global _sessions, _sessions_lock

    @wraps(function)
    def decorated(*args, **kwargs):
        ret = _sspi_handler(session)
        if ret is not None:
            return ret
        else:
            uuid = session['uuid']
            with _sessions_lock:
                _session = _sessions[uuid]
                lock = _session['lock']
                lock.acquire()
            try:
                if 'username' not in _session:
                    # get username through impersonalisation
                    with Impersonate(_session):
                        current_user = _get_user_name()
                    g.current_user = current_user
                    _session['username'] = current_user
                    _session['last_access'] = datetime.datetime.now()
                else:
                    g.current_user = _session['username']
            finally:
                lock.release()
            # call route function
            response = function(g.current_user, *args, **kwargs)
            response = make_response(response)
            return response

    return decorated


def authenticate(function):
    '''
    Require that the wrapped view function only be called by users
    authenticated with SSPI. 
    
    :param function: flask view function
    :type function: function
    :returns: decorated function
    :rtype: function
    '''
    global _sessions, _sessions_lock

    @wraps(function)
    def decorated(*args, **kwargs):
        ret = _sspi_handler(session)
        if ret is not None:
            return ret
        else:
            uuid = session['uuid']
            with _sessions_lock:
                _session = _sessions[uuid]
                lock = _session['lock']
                lock.acquire()
            try:
                if 'username' not in _session:
                    # get username through impersonalisation
                    with Impersonate(_session):
                        current_user = _get_user_name()
                    g.current_user = current_user
                    _session['username'] = current_user
                    _session['last_access'] = datetime.datetime.now()
                else:
                    g.current_user = _session['username']
            finally:
                lock.release()
            # call route function
            response = function(*args, **kwargs)
            if response:
                response = make_response(response)
            return response

    return decorated
