#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15787);
 script_bugtraq_id( 11727 );
 script_version("$Revision: 1.3 $");
 
 name["english"] = "WebGUI Unspecified Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains a CGI script that is prone to an
unspecified remote flaw. 

Description :

The remote host is running WebGUI, a content management system from
Plain Black Software. 

According to its banner, the version of this software on the remote is
earlier than 6.2.9 and thus vulnerable to an undisclosed remote
vulnerability. 

See also : 

http://sourceforge.net/project/shownotes.php?release_id=284011

Solution : 

Upgrade to WebGUI 6.2.9 or newer.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of WebGUI";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);

if ( 'content="WebGUI' >< res && egrep(pattern:".*meta name=.generator.*content=.WebGUI ([0-5]\.|6\.([01]\.|2\.[0-8][^0-9]))", string:res) )
  security_warning(port);
