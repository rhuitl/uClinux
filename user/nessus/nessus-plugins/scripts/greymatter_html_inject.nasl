#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: poizon@securityinfo.ru
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(19752);
 script_bugtraq_id(14703);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "Greymatter gm.cgi HTML injection flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Greymatter, an opensource weblogging and 
journal software written in perl.

A vulnerability exists in this version which may allow 
an attacker to execute arbitrary HTML and script code in
the context of the user's browser.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote Greymatter";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
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
include("global_settings.inc");

port = get_http_port(default:80);

if ( !get_port_state(port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/gm.cgi"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if (egrep(pattern:'<META NAME="Generator" CONTENT="Greymatter (0\\.|1\\.([0-2][0-9]*[a-z]?|3|3\\.[01]))">', string:r)  )
 {
   security_warning(port);
   exit(0);
 }
}

if (thorough_tests) dirs = make_list("/greymatter", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}

