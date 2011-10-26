#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15442);
 script_version("$Revision: 1.5 $");

 script_cve_id("CVE-2004-1580");
 script_bugtraq_id(11337);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"10584");

 name["english"] = "CubeCart SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is susceptible to a SQL
injection attack. 

Description :

There is a SQL injection issue in the remote version of CubeCart that
may allow an attacker to execute arbitrary SQL statements on the remote
host and to potentially overwrite arbitrary files on the remote system,
by sending a malformed value to the 'cat_id' argument of the file
'index.php'. 

See also :

http://seclists.org/lists/bugtraq/2004/Oct/0051.html
http://www.cubecart.com/site/forums/index.php?showtopic=4065

Solution : 

Upgrade to CubeCart 2.0.2 or later.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection in CubeCart";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencies("cubecart_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 res = http_keepalive_send_recv(port:port, data:http_get(item:loc + "/index.php?cat_id=42'", port:port));
 if ("mysql_fetch_array()" >< res) security_warning(port);
}
