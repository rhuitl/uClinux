#
# (C) Tenable Network Security
#


if (description) {
  script_id(17194);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-0512");
  script_bugtraq_id(11220, 12608);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"14021");

  name["english"] = "Mambo Open Source Tar.php Remote File Include Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a remote
file include flaw. 

Description :

The version of Mambo Open Source on the remote host fails to properly
sanitize input passed through the 'mosConfig_absolute_path' parameter
of the 'Tar.php' script.  Provided PHP's 'register_globals' setting is
enabled, a remote attacker may exploit this vulnerability to cause
code to be executed in the context of the user running the web service
or to read arbitrary files on the target. 

See also :

http://forum.mamboserver.com/showthread.php?t=32119
http://mamboxchange.com/frs/shownotes.php?group_id=5&release_id=3054

Solution : 

Upgrade to Mambo Open Source 4.5.2.1 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Tar.php Remote File Include Vulnerability in Mambo Open Source";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  req = http_get(
    item:string(
      dir, "/includes/Archive/Tar.php?",
      "mosConfig_absolute_path=../../CHANGELOG%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if ("Mambo is Free Software" >< res) security_warning(port);
}
