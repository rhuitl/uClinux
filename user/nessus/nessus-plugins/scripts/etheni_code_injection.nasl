#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Cc: vulnwatch@vulnwatch.org
# Date: Mon, 06 Jan 2003 21:25:43 +0100
# Subject: [VulnWatch] E-theni (PHP)


if(description)
{
 script_id(11497);
 script_cve_id("CVE-2003-1256");
 script_bugtraq_id(6970);
 script_version ("$Revision: 1.10 $");

 name["english"] = "E-Theni code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using E-Theni.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : See http://www.phpsecure.org or contact the vendor for a patch
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of aff_list_langue.php";
 
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

if ( ! can_host_php(port:port) ) exit(0);


dirs = make_list(cgi_dirs(), "/e-theni");



foreach dir (dirs)
{
 req = http_get(item:"/admin_t/include/aff_liste_langue.php?rep_include=http://xxxxxxxx/",
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*http://xxxxxxxx/para_langue\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}
