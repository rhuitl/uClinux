#
# (C) Tenable Network Security
#


if (description) {
  script_id(20992);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1040");
  script_bugtraq_id(16919);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"23614");

  script_name(english:"vBulletin Email Field Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks version number of vBulletin");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by a
cross-site scripting issue. 

Description :

According to its banner, the version of vBulletin installed on the
remote host does not properly sanitize user-supplied input to the
email field in the 'profile.php' script.  Using a specially-crafted
email address in his profile, an authenticated attacker can leverage
this issue to inject arbitrary HTML and script code into the browsers
of users who views the attacker's profile. 

See also :

http://www.securityfocus.com/archive/1/426537/30/0/threaded
http://www.vbulletin.com/forum/showthread.php?t=176170

Solution :

Upgrade to vBulletin 3.5.4 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("vbulletin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([0-2]\.|3\.([0-4]\.|5\.[0-3]))") {
    security_note(port);
    exit(0);
  }
}
