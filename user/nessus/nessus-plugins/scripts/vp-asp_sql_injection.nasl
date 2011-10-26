# 
# (C) Tenable Network Security
#

if (description)
{
 script_id(11786);
 script_cve_id("CVE-2002-1919");
 script_bugtraq_id(4861);
 script_version ("$Revision: 1.8 $");

 script_name(english:"VP-ASP SQL Injection");
 desc["english"] = "
The remote host is using the VP-ASP software suite.

This set of CGIs is vulnerable to a SQL injection bug which may allow 
an attacker to take the control of the server as an administrator.
From there, he can obtain the list of customers, steal their credit
card information and more.

In addition to this, this software is vulnerable to various
file disclosure and cross site scripting flaws.

Solution : Upgrade to the latest version of VP-ASP.
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if ProductCart is vulnerable to a sql injection attack");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item:dir + "/shopexd.asp?catalogid='42", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 if(egrep(pattern:"'catalogid='42'", string:res))
 {
  security_hole(port);
  exit(0);
 }
}
