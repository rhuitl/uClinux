#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


if (description) {
  script_id(13859);
  script_version ("$Revision: 1.2 $");
 
  name["english"] = "osTicket Support Address DoS";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of osTicket 1.2.7 or
earlier.  Such versions are subject to a denial of service attack in
open.php if osTicket is configured to receive mails using aliases.  If
so, a remote attacker can generate a mail loop on the target by opening
a ticket with the support address as the contact email address. For 
details, see :

  - http://www.osticket.com/forums/showthread.php?t=301

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of osTicket installed 
***** there. It has no way of knowing which method osTicket uses to
***** retrieve mail.

Solution : Configure osTicket to receive mail using POP3.

Risk factor : None / High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Support Address DoS osTicket";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "osticket_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for Support Address DoS vulnerability in osTicket on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/osticket"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ereg(pattern:"^1\.(0|1|2|2\.[0-7])$", string:ver)) {
      security_hole(port);
      exit(0);
    }
  }
}
