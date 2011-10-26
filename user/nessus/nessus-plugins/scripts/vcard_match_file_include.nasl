#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to a remote
file include vulnerability. 

Description :

The remote host appears to be running vCard, a web-based electronic
postcard application from Belchior Foundry and written in PHP. 

The version of vCard installed on the remote host fails to sanitize
the 'match' parameter before using it in the 'admin/define.inc.php'
script to read other files.  By leveraging this flaw, an
unauthenticated attacker may be able to execute script files from
third-party hosts. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-10/0347.html

Solution : 

Restrict access to the vCard's 'admin' directory using, say, a
.htaccess file. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20133);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3332");
  script_bugtraq_id(15207);

  script_name(english:"vCard match Parameter Remote File Inclusion Vulnerability");
  script_summary(english:"Checks for match parameter remote file inclusion vulnerability in vCard");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

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
if (thorough_tests) dirs = make_list("/vcard", "/vcards", "/ecard", "/cards", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read from a non-existent host.
  req = http_get(
    item:string(
      dir, "/admin/define.inc.php?",
      "match=http://xxxx./"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a PHP error.
  if (
    "Call to a member function on a non-object" >< res &&
    "/admin/define.inc.php" >< res
  ) {
    if (report_verbosity > 0) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        res
      );
    }
    else report = desc;

    security_warning(port, data:report);
    exit(0);
  }
}
