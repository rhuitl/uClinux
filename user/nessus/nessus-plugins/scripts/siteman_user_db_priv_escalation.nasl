#
# (C) Tenable Network Security
#

if(description)
{
  script_id(16216);

  script_cve_id("CVE-2005-0305");
  script_bugtraq_id(12304, 12558);
  script_xref(name:"OSVDB", value:"13131");

  script_version("$Revision: 1.6 $");
  
  script_name(english:"Siteman Page User Database Privilege Escalation Vulnerability");

 desc["english"] = "
The remote host is running Siteman, a web-based content management system
written in PHP.

The remote version of this software is vulnerable to a privilege escalation
vulnerability.

An attacker with a valid username and password may escalate his privileges
by making a specially crafted request to the remote server.

Solution: Upgrade to SiteMan 1.1.11 or newer.
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks SiteMan's version");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

foreach dir ( cgi_dirs() )
{
buf = http_get(item:dir + "/forum.php", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if( '<meta name="generator" content="Siteman ' >< r )
{
  line = egrep(pattern:'<meta name="generator" content="Siteman (0\\.|1\\.(0|1\\.([0-9][^0-9]|10[^0-9])))', string:r);
  if ( line ) 
  {
  security_warning(port);
  exit(0);
  }
 }
}
