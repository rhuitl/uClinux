#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#

if (description) {
  script_id(20379);
  script_version("$Revision: 1.2 $");
  script_bugtraq_id(16088);

  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
several flaws. 

Description :

According to its version number, the remote version of this software
is vulnerable to Javascript injection issues using 'url' bbcode tags
and, if HTML tags are enabled, HTML more generally.  This may allow an
attacker to inject hostile Javascript into the forum system, to steal
cookie credentials or misrepresent site content.  When the form is
submitted the malicious Javascript will be incorporated into
dynamically generated content. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040204.html 
http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=352966

Solution : 

Upgrade to phpBB version 2.0.19 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

  script_name(english:"phpBB <= 2.0.18 Multiple Cross-Site Scripting Flaws");
  script_summary(english:"Checks for multiple cross-site scripting flaws in phpBB <= 2.0.18");

  script_description(english:desc["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006 David Maciejak");

  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);


matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
	version = matches[1];
	if ( ereg(pattern:"^([01]\..*|2\.0\.([0-9]|1[0-8])[^0-9])", string:version)) {
	   security_note(port);
	   exit(0);
	}
}
