#
# (C) Tenable Network Security
#
# From: "JvdR" <thewarlock@home.nl>
# To: <bugtraq@securityfocus.com>
# Subject: Multiple Vulnerabilities in Invision Power Board v1.3.1 Final.
# Date: Tue, 8 Jun 2004 16:53:11 +0200
#

if(description)
{
  script_id(12268);
  script_bugtraq_id(10511);
  script_version("$Revision: 1.4 $");
  name["english"] = "Invision Power Board ssi.php SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a SQL
injection vulnerability.

Description :

A vulnerability exists in the version of Invision Power Board on the
remote host such that unauthorized users can inject SQL commands
through the 'ssi.php' script.  An attacker may use this flaw to gain
the control of the remote database.

See also :

http://archives.neohapsis.com/archives/bugtraq/2004-06/0116.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Invision Power Board ssi.php SQL Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

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
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  req = http_get(item:string(dir, "/ssi.php?a=out&type=xml&f=0)'"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( res == NULL ) exit(0);

  if ( "AND t.approved=1 ORDER BY t.last_post" >< res )
    security_warning(port);
}
