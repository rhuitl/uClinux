#
# (C) Tenable Network Security
#


if(description)
{
  script_id(12025);
  script_bugtraq_id(9445);
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"3616");

  script_version("$Revision: 1.5 $");
  name["english"] = "Mambo Code injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by a
remote file include vulnerability. 

Description :

There is a flaw in the installed version of Mambo Open Source that may
allow an attacker to execute arbitrary remote PHP code on this host
because it fails to sanitize input to the 'mosConfig_absolute_path' of
'modules/mod_mainmenu.php' before using it to include PHP code from
another file. 

Note that, for exploitation of this issue to be successful, PHP's
'register_globals' setting must be enabled. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2004-01/0141.html
http://www.nessus.org/u?472f1d6d

Solution : 

Upgrade to Mambo Open Source 4.5 Stable (1.0.2) or later. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detect mambo code injection vuln";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 req = http_get(item:string(dir, "/modules/mod_mainmenu.php?mosConfig_absolute_path=http://xxxxxxx"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);

 if ("http://xxxxxxx/modules" >< res ) security_warning(port);
}
