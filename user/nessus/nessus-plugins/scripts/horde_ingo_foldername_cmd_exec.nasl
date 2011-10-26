#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22900);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-5449");
  script_bugtraq_id(20637);

  script_name(english:"Ingo Foldername Command Execution Vulnerability");
  script_summary(english:"Checks version number of Ingo");

  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
command execution vulnerability. 

Description :

According to its version number, the instance of Ingo installed on the
remote host fails to properly sanitize mailbox destinations in filter
rules.  By using a folder name beginning with '|' as a mailbox
destination, an authenticated remote attacker may be able to exploit
this issue to execute arbitrary code on the remote host, subject to
the permissions of the web server user id. 

See also :

http://bugs.horde.org/ticket/?id=4513
http://lists.horde.org/archives/announce/2006/000296.html

Solution :

Upgrade to Ingo version H3 (1.1.2) or later. 

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("horde_ingo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# Only run the plugin if we're being paranoid to avoid false-positives,
# which might arise because the software is open-source.
if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/horde_ingo"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^H3 +\(1\.(0\..+|1([^.]*|\.[01]))\)") security_warning(port);
}
