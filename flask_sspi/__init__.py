import sys

modulename = 'flask_sspi_fake'
if modulename in sys.modules:  # once imported keep using stubs
    from flask_sspi_fake import *
else:
    from ._common import requires_authentication, init_sspi, authenticate, Impersonate
