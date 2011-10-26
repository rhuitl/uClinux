#
# This script is (C) Tenable Network Security
#
#

if(description)
{
 script_id(15988);
 script_bugtraq_id(11984);
 script_version ("$Revision: 1.5 $");

 name["english"] = "WordPress Multiple Flaws (XSS, HTML Injection, SQL Injection)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains several PHP scripts that are prone to SQL
injection and cross-site scripting attacks. 

Description : 

According to its banner, the remote version of WordPress is vulnerable
to various flaws which may allow an attacker to perform an HTML
injection attack against the remote host or allow an attacker to execute
arbitrary SQL statements against the remote database. 

See also :

http://www.securityfocus.com/archive/1/384659

Solution : 

Upgrade to WordPress 1.2.2 or greater.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";


 script_description(english:desc["english"]);
 summary["english"] = "Checks for multiple flaws in WordPress < 1.2.2";
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("wordpress_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "(0\.|1\.([01]|2[^0-9]|2\.[01][^0-9]))") {
    security_warning(port); 
    exit(0);
  }
}
