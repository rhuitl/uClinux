# 
# (C) Tenable Network Security
# 
# This script was written by shruti@tenablesecurity.com
# based on the scripts written by Renaud Deraison.
#
# Reference: y3dips
#


if(description)
{
 script_id(15909);
 script_bugtraq_id(11817);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "PAFileDB Error Message Path Disclosure Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by an
information disclosure issue. 

Description :

There is a flaw in the remote version of paFileDB that may let an
attacker obtain the physical path of the remote installation by
sending a malformed request to one of the scripts 'admins.php',
'category.php', or 'team.php'.  This information may help an attacker
make more focused attacks against the remote host. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=110245123927025&w=2

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for psFileDB path disclosure";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencies("pafiledb_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  req = http_get(item:dir + "/includes/admin/admins.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if("Fatal error: Call to undefined function" >< res)
  {
    security_note(port);
    exit(0);
  }

  req = http_get(item:dir + "/includes/admin/category.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if("Fatal error: Call to undefined function" >< res)
  {
    security_note(port);
    exit(0);
  }

  req = http_get(item:dir + "/includes/team.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if("failed to open stream:" >< res)
  {
    security_note(port);
    exit(0);
  }
}
