#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10015);
 script_bugtraq_id(896);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0039");
 name["english"] = "AltaVista Intranet Search";
 name["francais"] = "AltaVista Intranet Search";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to read the content of any files on the remote 
host (such as your configuration files or other sensitive data) 
by using the Altavista Intranet Search service, and performing 
the request:

	GET /cgi-bin/query?mss=%2e%2e/config

Bugtraq ID : 896

Solution : 
- edit <install-dir>/httpd/config file and change MGMT_IPSPEC from
'0.0.0.0/0' to a specific IP such as '127.0.0.1/32'
- stop page gathering via the management interface
- restart Altavista Search Service (to re-read config file)
- restart page gathering if necessary
- change the username/password through the management interface to bogus
information
- exploit server and download ../logs/mgtstate  (puts file in cache)
  http://localhost:9000/cgi-bin/query?mss=../logs/mgtstate
- change the username/password through the management interface to something
different (but not used anywhere else)
- avoid restarting the Altavista service or clearing the cache

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if query?mss=... reads arbitrary files";
 summary["francais"] = "Détermine si query?mss=... lit des fichiers arbitraires";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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
item = "/cgi-bin/query?mss=%2e%2e/config";
req = http_get(item:item, port:port);
result = http_keepalive_send_recv(port:port, data:req);
if( result == NULL ) exit(0);
if("MGMT_PW" >< result){
	security_hole(port);
	exit(0);
	}
