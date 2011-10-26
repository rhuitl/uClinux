#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  George A. Theall, <theall@tifaware.com>
#
#  Ref: Nuno Loureiro <nuno@eth.pt>
#
#  This script is released under the GNU GPL v2
#


if (description) {
  script_id(15616);
  script_version ("$Revision: 1.3 $"); 
  script_bugtraq_id(4444);
  script_cve_id("CVE-2002-0181");
  
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"5345");
  }

  name["english"] = "Horde IMP status.php3 XSS";
  script_name(english:name["english"]);

  desc["english"] = "

The remote host is running at least one instance of Horde IMP in which the
status.php3 script is vulnerable to a cross site scripting attack since
information passed to it is not properly sanitized.

Solution : Upgrade to IMP version 2.2.8 or later.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for status.php3 XSS flaw in Horde IMP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");


  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
  
  script_dependencie("global_settings.nasl", "imp_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/imp"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    url = string(
      dir, 
      # nb: if you change the URL, you probably need to change the 
      #     pattern in the egrep() below.
      "/status.php3?script=<script>foo</script>"
    );
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (isnull(res)) exit(0);
           
    if (egrep(string:res, pattern:'<script>foo</script>')) {
      security_warning(port);
      exit(0);
    }
  }
}
