#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: <steven@lovebug.org>.
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15479);
 script_cve_id("CVE-2004-1594");
 script_bugtraq_id(11407, 11393);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "FuseTalk forum XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using FuseTalk, a web based discussion forum.

A vulnerability exists in the script 'tombstone.cfm' which may allow 
an attacker to execute arbitrary HTML and script code in the context 
of the user's browser.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks XSS in FuseTalk";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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

function check(loc)
{
 req = http_get(item:string(loc, "/tombstone.cfm?ProfileID=<script>foo</script>"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ( "FuseTalk Inc." >< r && egrep(pattern:"<script>foo</script>", string:r)  )
 {
   security_warning(port);
 }
 exit(0);
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

