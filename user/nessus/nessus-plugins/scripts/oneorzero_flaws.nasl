#
# (C) Tenable Network Security
#
#
# Ref:
#  From: "Frog Man" <leseulfrog@hotmail.com>
#  To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
#  Date: Thu, 15 May 2003 19:06:40 +0200
#  Subject: [VulnWatch] OneOrZero Security Problems (PHP)


if (description)
{
 script_id(11643);
 script_cve_id("CVE-2003-0303");
 script_bugtraq_id(7609, 7611);
 script_version ("$Revision: 1.8 $");

 script_name(english:"OneOrZero SQL injection");
 desc["english"] = "
The remote host is running OneOrZero, an online helpdesk.

There are multiple flaws in this software which may allow an attacker
to insert arbitrary SQL commands in the remote database, or even
to gain administrative privileges on this host. 


Solution : Unofficial patches are available at http://www.phpsecure.info
Risk factor : High";


 script_description(english:desc["english"]);
 script_summary(english:"Determines OneOrZero is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


dir = make_list("/help", "/support", "/supporter", "/support/helpdesk", "/helpDesk", "/helpdesk", cgi_dirs());
		

foreach d (dir)
{
 req = http_get(item:d + "/supporter/tupdate.php?groupid=change&sg='", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("SQL" >< res && "' where id='" >< res){ security_hole(port); exit(0); }
}
