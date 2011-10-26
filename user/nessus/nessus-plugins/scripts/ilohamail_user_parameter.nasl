#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(14637);
  script_bugtraq_id(9131);
  script_version("$Revision: 1.2 $");

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 09/2004)
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"2879");
  }
 
  name["english"] = "IlohaMail User Parameter Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of IlohaMail version
0.8.10 or earlier.  Such versions do not properly sanitize the 'user'
parameter, which could allow a remote attacker to execute arbitrary
code either on the target or in a victim's browser when a victim views
a specially crafted message with an embedded image as long as PHP's
magic quotes setting is turned off (it's on by default) and the MySQL
backend is in use. 

For a discussion of this vulnerability, see :

  http://sourceforge.net/mailarchive/forum.php?thread_id=3589704&forum_id=27701

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of IlohaMail 
***** installed there.

Solution : Upgrade to IlohaMail version 0.8.11 or later.

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for User Parameter vulnerability in IlohaMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for IlohaMail User Parameter vulnerability on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ver =~ "^0\.([0-7].*|8\.([0-9]|10)(-Devel)?$)") {
      security_warning(port);
      exit(0);
    }
  }
}
