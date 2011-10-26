#
# This script was written by Renaud Deraison
#
# GPL
#
# References:
# Date: 27 Mar 2003 17:26:19 -0000
# From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server
#

if(description)
{
 script_version ("$Revision: 1.4 $");
 script_id(11491);
 script_bugtraq_id(7207, 7208);
 script_name(english:"Sambar default CGI info disclosure");
 
 
 desc["english"] = "
The remote web server is running two CGIs (environ.pl and 
testcgi.exe) which, by default, disclose a lot of information
about the remote host (such as the physical path to the CGIs on
the remote filesystem).


Solution : Delete these two CGIs
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for testcgi.exe and environ.pl";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


req = http_get(item:"/cgi-bin/testcgi.exe", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if("SCRIPT_FILENAME" >< res ) {
	security_warning(port);
	exit(0);
	}
	
	
req = http_get(item:"/cgi-bin/environ.pl", port:port);	
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if("DOCUMENT_ROOT" >< res) security_warning(port);
