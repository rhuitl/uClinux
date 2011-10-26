#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
# Update - 13.9.01 - Felix Huber <huberfelix@webtopia.de>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10581);
 script_bugtraq_id(1314);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0538");
 name["english"] = "Cold Fusion Administration Page Overflow";
 name["francais"] = "Cold Fusion Administration Page Overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "A denial of service vulnerability exists within the Allaire
ColdFusion web application server (version 4.5.1 and earlier) which allows an 
attacker to overwhelm the web server and deny legitimate web page requests.

By downloading and altering the login HTML form an attacker can send overly 
large passwords (>40,0000 chars) to the server, causing it to stop responding.

Solution: Use HTTP basic authentication to restrict access to this page or
remove it entirely if remote administration is not a requirement. 
A patch should be available from allaire - www.allaire.com..

Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cfide/administrator/index.cfm";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Matt Moore",
		francais:"Ce script est Copyright (C) 2000 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 # CFIDE will work with CF Linux also
 req = http_get(item:"/CFIDE/administrator/index.cfm",
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if("PasswordProvided" >< r && "cf50" >!< r)	
 	security_hole(port);

}
