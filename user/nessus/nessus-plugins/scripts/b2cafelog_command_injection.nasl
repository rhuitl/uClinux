#
# This script is (C) Tenable Network Security
#
#
# Ref:
#
# From: pokleyzz <pokleyzz@scan-associates.net>
# To: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
# Cc: tech@scan-associates.net
# Subject: [VulnWatch] b2 cafelog 0.6.1 remote command execution.



if(description)
{
 script_id(11667);
 script_bugtraq_id(4673, 7738, 7782, 7783, 7786);
 script_cve_id("CVE-2002-0734");
 script_version ("$Revision: 1.9 $");

 name["english"] = "b2 cafelog code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using the b2 cafelog CGI suite which is installed.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to the latest version
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of gm-2-b2.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
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
if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/b2-tools/gm-2-b2.php?b2inc=http://xxxxxxxx"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*http://xxxxxxxx/b2functions\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}



dirs = make_list(cgi_dirs());


foreach dir (dirs)
{
 check(loc:dir);
}
