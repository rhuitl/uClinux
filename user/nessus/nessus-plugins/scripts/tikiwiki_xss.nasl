#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Florian Hengartner <hengartnerf@users.sourceforge.net>
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(15709);
  script_bugtraq_id(14121);
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:7449);
  
  script_version("$Revision: 1.5 $");
  script_name(english:"TikiWiki tiki-error.php XSS");

 
 desc["english"] = "
The remote host is running TikiWiki, a content management 
system written in PHP.

The remote version of this software is vulnerable to cross-site 
scripting attacks in tiki-error.php script due to a lack of user 
input sanitization.

Solution: Upgraded to version 1.7.8 or newer.
Risk factor : Medium";

  script_description(english:desc["english"]);

  script_summary(english:"Checks TikiWiki version");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www");
 script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#now the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item: loc + "/tiki-index.php", port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if( "This is Tiki v" >< r && egrep(pattern:"This is Tiki v(0\.|1\.[0-6]\.|1\.7\.[0-7][^0-9])", string:r) )
 {
 	security_warning(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
