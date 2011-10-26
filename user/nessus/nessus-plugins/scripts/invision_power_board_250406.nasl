#
# (C) Tenable Network Security
#


if (description) 
{
  script_id(21307);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-2059", "CVE-2006-2060", "CVE-2006-2061");
  script_bugtraq_id(17690, 17695);
  if (defined_func("script_xref"))
  {
    script_xref(name:"OSVDB", value:"25005");
    script_xref(name:"OSVDB", value:"25008");
  }

  script_name(english:"Invision Power Board 2.x.x < 04-25-06 Multiple Vulnerabilities");
  script_summary(english:"Checks for ck parameter SQL injection vulnerability in IPB");
 
  desc = "
Synopsis : 

The remote web server contains a PHP application that is susceptible
to multiple types of attacks. 

Description :

The installation of Invision Power Board on the remote host fails to
sanitize input to the 'ck' parameter of the 'index.php' script before
using it in database queries.  An unauthenticated attacker may be able
to leverage this issue to disclose sensitive information, modify data,
or launch attacks against the underlying database. 

In addition, the application reportedly allows for execution of
arbitrary PHP code contained in a posting due to a flaw in the
'search.php' script, remote file includes (requires admin capability),
and cross-site scripting attacks using specially-crafted JPEG file. 

See also :

http://www.securityfocus.com/archive/1/431990/30/0/threaded
http://forums.invisionpower.com/index.php?showtopic=213374

Solution :

Apply the IPB 2.x.x 04-25-06 Security Update referenced in the vendor
URL above. 

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(pattern:"^(.+) under (/.*)$", string:install);
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL syntax error.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "act=task&",
      "ck='", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error.
  if (egrep(pattern:string("mySQL query error: SELECT .+task_manager +WHERE task_cronkey=''", SCRIPT_NAME), string:res))
  {
    security_warning(port);
    exit(0);
  }
}
