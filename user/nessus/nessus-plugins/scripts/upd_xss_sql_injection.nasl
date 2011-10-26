#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# ref: Morinex Eneco <m0r1n3x@gmail.com>
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18260);
 script_cve_id("CVE-2005-1614", "CVE-2005-1615");
 script_bugtraq_id(13621, 13622);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Ultimate PHP Board ViewForum.PHP SQL injection and XSS flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Ultimate PHP Board (UPB).

The remote version of this software is vulnerable to cross-site scripting 
attacks, and SQL injection flaws.

Using a specially crafted URL, an attacker may execute arbitrary commands against
the remote SQL database or use the remote server to set up a cross site scripting
attack.

Solution : Upgrade to version 1.9.7 or newer.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for UPB";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if(egrep(pattern:"Powered by UPB Version :.* (0\.|1\.([0-8][^0-9]|9[^0-9]|9\.[1-6][^0-9]))", string:res))
 {
 	security_hole(port);
	exit(0);
 }
}
