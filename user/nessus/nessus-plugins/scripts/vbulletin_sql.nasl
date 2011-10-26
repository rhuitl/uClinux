#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14785);
 script_version("$Revision: 1.5 $");

 script_bugtraq_id(11193);
 script_xref(name:"OSVDB", value:"9993");

 name["english"] = "vBulletin SQL injection Issue";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is susceptible to a
SQL injection attack. 

Description :

According to its banner, the remote version of vBulletin is vulnerable
to a SQL injection issue.  It is reported that versions 3.0.0 through
to 3.0.3 are prone to this issue.  An attacker may exploit this flaw
to gain the control of the remote database. 

See also : 

http://www.vbulletin.com/forum/showthread.php?p=734250#post734250
http://www.vbulletin.com/forum/showthread.php?t=124876

Solution : 

Upgrade to vBulletin 3.0.4 or later.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of vBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("vbulletin_detect.nasl");
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
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if ( ver =~ '^3.0(\\.[0-3])?[^0-9]' ) security_warning(port);
}
