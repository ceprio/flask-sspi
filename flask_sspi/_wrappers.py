"""
UNUSED CODE - part of _common may come here later


from ._common import _sspi_handler, _sessions, session
from functools import wraps
from flask import g
from flask.helpers import make_response

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
            uuid=session['uuid']
            if 'username' not in _sessions[session['uuid']]:
                # get username through impersonalisation
                _sa = _sessions[uuid]['sa']
                _sa.ctxt.ImpersonateSecurityContext()
                current_user = _get_user_name()
                g.current_user = current_user
                _sessions[uuid]['username'] = current_user
                _sessions[uuid]['last_access'] =  datetime.datetime.now()
                _sa.ctxt.RevertSecurityContext()
            else:
                g.current_user = _sessions[uuid]['username']
            # call route function
            response = function(*args, **kwargs)
            response = make_response(response)
            return response 
    return decorated

def impersonate(function):
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
            _sa = _sessions[session['uuid']]['sa']
            _sa.ctxt.ImpersonateSecurityContext()
            current_user = _get_user_name()
            g.current_user = current_user
            _sessions[session['uuid']]['username'] = current_user
            _sessions[session['uuid']]['last_access'] =  datetime.datetime.now()
            try:
                 # call route function
                response = function(*args, **kwargs)
            finally:
                _sa.ctxt.RevertSecurityContext()
            response = make_response(response)
            return response 
    return decorated
"""
