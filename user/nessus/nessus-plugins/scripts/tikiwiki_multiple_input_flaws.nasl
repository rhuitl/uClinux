#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: JeiAr <security@gulftech.org>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14364);
 script_cve_id(
   "CVE-2004-1923", 
   "CVE-2004-1924", 
   "CVE-2004-1925", 
   "CVE-2004-1926", 
   "CVE-2004-1927", 
   "CVE-2004-1928"
 );
 script_bugtraq_id(10100);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "TikiWiki multiple input validation vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Tiki Wiki, a content management system written
in PHP.

The remote version of this software is vulnerable to multiple vulnerabilities 
which have been identified in various modules of the application. 
These vulnerabilities may allow a remote attacker to carry out various attacks 
such as path disclosure, cross-site scripting, HTML injection, SQL injection, 
directory traversal, and arbitrary file upload. 

Solution : Upgrade to TikiWiki 1.8.2 or newer
Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of TikiWiki";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
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
if(!can_host_php(port:port))exit(0);
function check(loc)
{
 req = http_get(item: loc + "/tiki-index.php", port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if( egrep(pattern:"This is Tiki v(0\.|1\.[0-7]\.|1\.8\.[0-1][^0-9])", string:r) )
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

