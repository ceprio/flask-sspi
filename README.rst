Flask-SSPI
==============

THIS DOES NOT AS EXPECTED:
- NEEDS ONE sa PER SESSION
- NEEDS A USER DATABASE FOR SESSION HANDLING AND USER QUICK IDENTIFICATION WITH CACHE CLEARING AFTER A CERTAIN TIME


Flask-SSPI is an extension to `Flask`_ that allows you to trivially add
`NTLM`_ based authentication to your website. It depends on both Flask and
`sspi`. You can install the requirements from PyPI with
`easy_install` or `pip` or download them by hand.


