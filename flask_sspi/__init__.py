import sys

if 'flask_sspi_fake' in sys.modules:  # once imported keep using stubs
    from flask_sspi_fake import *
else:
    from ._common import requires_authentication, init_sspi, authenticate, Impersonate
