#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10389);
 script_bugtraq_id(1153);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0429");
 
 name["english"] = "Cart32 ChangeAdminPassword";
 name["francais"] = "Cart32 ChangeAdminPassword";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The Cart32 e-commerce shopping cart is installed.

This software contains several security flaws :

	- it may contain a backdoor
	- users may be able to change the admin password remotely


See also : http://www.cerberus-infosec.co.uk/advcart32.html
Solution : Use Cart32 version 5.0 or newer
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Cart32";
 summary["francais"] = "Détermine la présence de Cart32";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
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
if ( !port || ! get_port_state(port) ) exit(0);

foreach dir (cgi_dirs())
{
 req = http_get(item:dir + "/cart32.exe", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"<title>Cart32 [0-2]\.", string:res) )
	{
	security_hole(port);
	exit(0);
	}
}
	
