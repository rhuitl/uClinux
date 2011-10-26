#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a Python application that is affected
by a log spoofing vulnerability. 

Description :

The version of Mailman installed on the remote host fails to sanitize
user-supplied input before writing it to the application's 'error'
log.  An unauthenticated remote attacker can leverage this flaw to
spoof log messages. 

In addition, the application reportedly is affected by a denial of
service issue involving headers that do not conform to RFC 2231 as
well as several cross-site scripting vulnerabilities. 

See also :

http://moritz-naumann.com/adv/0013/mailmanmulti/0013.txt
http://lists.grok.org.uk/pipermail/full-disclosure/2006-September/049453.html
http://sourceforge.net/project/shownotes.php?release_id=444295&group_id=103
http://mail.python.org/pipermail/mailman-announce/2006-September/000086.html

Solution :

Upgrade to Mailman version 2.1.9 rc1 or later. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";


if (description)
{
  script_id(22307);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4624");
  script_bugtraq_id(19831);

  script_name(english:"Mailman Log Spoofing Vulnerability");
  script_summary(english:"Checks if Mailman filters invalid chars from PATH_INFO");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("mailman_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/Mailman"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw.
  list = "mailman";
  req = http_get(
    item:string(dir, "/listinfo/", list, "%0a", SCRIPT_NAME), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if the listname was not sanitized properly.
  if (string('No such list <em>', list, '\n', SCRIPT_NAME, '</em>') >< res)
  {
    security_note(port);
    exit(0);
  }
}
