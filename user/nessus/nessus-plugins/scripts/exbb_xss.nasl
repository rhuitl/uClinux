#
# (C) Tenable Network Security
#

if(description)
{
  script_id(16223);
  script_bugtraq_id(12306);
  script_version("$Revision: 1.3 $");
  
  script_name(english:"ExBB Netsted BBcode Remote Script Injection");

 desc["english"] = "
The remote host is running ExBB, a bulletin board system written in PHP

The remote version of this software is vulnerable to a script injection
vulnerability.

An attacker may post a forum comment in the remote application, containing
rogue javascript tags which will be executed in the browsers of legitimate
visitors of the remote web site.

Solution: Upgrade to ExBB 1.9.2 (when available) or newer
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks ExBB's version");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

foreach dir ( cgi_dirs() )
{
buf = http_get(item:dir + "/search.php", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if( 'class=copyright>ExBB</a>' >< r )
{
  line = egrep(pattern:'Powered by <a href=.* target=_blank class=copyright>ExBB</a> (0\\.|1\\.[0-8][^0-9]|1\\.9[^.]|1\\.9\\.[01][^0-9])', string:r);
  if ( line ) 
  {
  security_warning(port);
  exit(0);
  }
 }
}
