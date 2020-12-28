import base64
import logging
logger = logging.getLogger(__name__)

from flask import Response
from flask import _request_ctx_stack as stack
from flask import make_response
from flask import request, session, g
from functools import wraps
from socket import gethostname
import os
import datetime
import uuid

_PKG_NAME = 'NTLM'
_sessions = {}


def _user_context_processor():
    if hasattr(g, "current_user") and g.current_user is not None:
        return dict(current_user=g.current_user)
    else:
        return {}


def init_sspi(app, service='HTTP', hostname=gethostname(), package='NTLM', add_context_processor=True):
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
    
    if add_context_processor:
        app.context_processor(_user_context_processor)


def _get_user_name():
     return os.getlogin()

 
def _init_session():
    logger.debug("Init session")
    session['uuid'] = uuid.uuid4().bytes
    _sessions[session['uuid']] = {}
    _sessions[session['uuid']]['sa'] = 'sspi.ServerAuth(_PKG_NAME)'  # one per session
    # TODO cleanup other entries


def _sspi_handler(session):
    global _sessions
    if 'uuid' not in session or session['uuid'] not in _sessions:
        _init_session()
    if 'username' in _sessions[session['uuid']]:
        if 30 * 60 < (datetime.datetime.now() - _sessions[session['uuid']]['last_access']).seconds:
            logger.debug('timed out.')
            del _sessions[session['uuid']]
            _init_session()
        else:
            logger.debug('Already authenticated')  
            _sessions[session['uuid']]['last_access'] = datetime.datetime.now()
            return None

    logger.debug("Negotiation complete")
    return None


class Impersonate():
    '''
    Class that creates a context for the impersonalisation of the client user. 
    May be used to get his name or group appartenance. Could also be used
    to make trusted connections with databases (not tested).
    
    Preferred usage:
        with Impersonate():
            ...
    '''
    
    def open(self):
        '''
        Start of the impersonalisation
        '''
        uuid = session['uuid']
        self._sa = _sessions[uuid]['sa']

    def close(self):
        '''
        End of the impersonalisation
        '''
        if self._sa:
            self._sa = None

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

    @wraps(function)
    def decorated(*args, **kwargs):
        ret = _sspi_handler(session)
        if ret is not None:
            return ret
        else:
            uuid = session['uuid']
            if 'username' not in _sessions[session['uuid']]:
                # get username through impersonalisation
                with Impersonate():
                    current_user = _get_user_name()
                g.current_user = current_user
                _sessions[uuid]['username'] = current_user
                _sessions[uuid]['last_access'] = datetime.datetime.now()
            else:
                g.current_user = _sessions[uuid]['username']
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

    @wraps(function)
    def decorated(*args, **kwargs):
        ret = _sspi_handler(session)
        if ret is not None:
            return ret
        else:
            uuid = session['uuid']
            if 'username' not in _sessions[session['uuid']]:
                # get username through impersonalisation
                with Impersonate():
                    current_user = _get_user_name()
                g.current_user = current_user
                _sessions[uuid]['username'] = current_user
                _sessions[uuid]['last_access'] = datetime.datetime.now()
            else:
                g.current_user = _sessions[uuid]['username']
            # call route function
            response = function(*args, **kwargs)
            if response:
                response = make_response(response)
            return response 

    return decorated
