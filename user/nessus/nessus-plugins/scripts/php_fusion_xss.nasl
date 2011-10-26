#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Espen Andersson
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15392);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"10348");
 script_version("$Revision: 1.5 $");
 
 name["english"] = "PHP-Fusion homepage address XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to 
cross-site scripting attacks.

Description :

A vulnerability exists in the remote version of PHP-Fusion that may
allow an attacker to execute arbitrary HTML and script code in the
context of the user's browser. 

Solution : 

Apply the patch for 4.01.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote PHP-Fusion";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("php_fusion_detect.nasl");
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

kb = get_kb_item("www/" + port + "/php-fusion");
if ( ! kb ) exit(0);

items   = eregmatch(pattern:"(.*) under (.*)", string:kb);
version =  items[1];

if ( ereg(pattern:"([0-3][.,]|4[.,]0[01]([^0-9]|$))", string:version) )
	security_warning(port);
