#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14359);
 script_bugtraq_id(10972);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "TikiWiki Unauthorized Page Access";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Tiki Wiki, a content management system written
in PHP.

The remote version of this software is vulnerable to a flaw which
may allow an attacker to bypass the permissions of individual Wiki pages.

An attacker may exploit this flaw to deface the remote web server or gain
access to pages he should otherwise not have access to.

Solution : Upgrade to TikiWiki 1.8.4
Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of TikiWiki";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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
 if( egrep(pattern:"This is Tiki v(0\.|1\.[0-7]\.|1\.8\.[0-3][^0-9])", string:r) )
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

