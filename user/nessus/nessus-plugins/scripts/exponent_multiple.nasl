#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16250);
 script_cve_id("CVE-2005-0309");
 script_bugtraq_id(12358);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Exponent CMS Multiple Cross-Site Scripting Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Exponent, a web based content management 
system implemented in PHP.

The remote version of this software is vulnerable to multiple cross
site scripting vulnerabilites due to a lack of filtering on user-supplied
input in files 'index.php' and 'mod.php'. An attacker may exploit this
flaw to perform a cross-site scripting attack against the remote host.

This software is vulnerable to multiple path disclosure vulnerabilities
in the susbsystem directory.

Solution : None at this time.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Exponent";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
  
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

function check(url)
{
req = http_get(item:string(url, "/subsystems/permissions.info.php"), port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if ( r == NULL ) exit(0);
if ( egrep(pattern:"<b>Fatal error</b>:  Call to undefined function:  pathos_core_version()", string:r))
 {
 security_warning(port);
 exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
