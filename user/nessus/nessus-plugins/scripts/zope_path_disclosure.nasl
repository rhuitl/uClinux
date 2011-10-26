#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# http://collector.zope.org/Zope/359
#

if(description)
{
 script_id(11234);
 script_bugtraq_id(5806);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Zope Installation Path Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an application server that is prone to
information disclosure. 

Description :

There is a minor security problem in all releases of Zope prior to
version 2.5.1b1 - they reveal the installation path when an invalid
XML RPC request is sent. 

See also :

http://collector.zope.org/Zope/359

Solution : 

Upgrade to Zope 2.5.1b1 / 2.6.0b1 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Zope installation directory";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/zope");
 exit(0);
}

# The script code starts here

include("http_func.inc");
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

s = http_open_socket(port);
if (! s) exit(0);

# The proof of concept request was:
# POST /Documentation/comp_tut HTTP/1.0
# Host: localhost
# Content-Type: text/xml
# Content-length: 93
# 
# <?xml version="1.0"?>
# <methodCall>
# <methodName>objectIds</methodName>
# <params/>
# </methodCall>
#
# but it does not seem to be necessary IIRC.

req = http_post(port: port, item: "/Foo/Bar/Nessus");
send(socket: s, data: req);
a = http_recv(socket: s);
if (egrep(string: a, 
         pattern: "(File|Bobo-Exception-File:) +(/[^/]*)*/[^/]+.py"))
  security_note(port);
http_close_socket(s);
