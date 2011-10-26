#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11727);
 script_bugtraq_id(4093);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-0273");
 
 
 name["english"] = "CWmail.exe vulnerability";
 name["francais"] = "CWMail.exe vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The CWMail.exe exists on this webserver.  
Some versions of this file are vulnerable to remote exploit.

An attacker may make use of this file to gain access to
confidential data or escalate their privileges on the Web
server.


Solution : remove it from the cgi-bin or scripts directory. 

Patch information: http://marc.theaimsgroup.com/?l=bugtraq&m=101362100602008&w=2

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the cwmail.exe file";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
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


foreach dir (cgi_dirs()) {
   req = http_get(item:dir + "/cwmail.exe", port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if( res == NULL ) exit(0);
   
   if (egrep (pattern:".*CWMail 2\.[0-7]\..*", string:res) ) {
   	security_hole(port);
	exit(0);
	}
}
