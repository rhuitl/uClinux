#
# (C) Tenable Network Security
#



if(description)
{
 script_id(16206);
 script_bugtraq_id(12154);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-1061");
 

 name["english"] = "Bugzilla Internal Error Cross Site Scripting Vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains a CGI which is vulnerable to a cross site
scripting vulnerability.

Description :

The remote host runs bugzilla, a web-based bug tracking system.

The remote Bugzilla installation, according to its version number
is vulnerable to a cross site scripting attack when rendering internal
errors containing user-supplied input.

Solution : 

Upgrade to Bugzilla 2.18.0 or newer

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of bugzilla";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("bugzilla_detect.nasl");
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

version = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!version)exit(0);


if(ereg(pattern:"(1\..*)|(2\.(0\..*|1[0-7]\..*))", string:version)) {
	security_note(port);
      } 
