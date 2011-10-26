#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if (description)
{
 script_id(10655);
script_cve_id("CVE-2001-0321");
 script_version ("$Revision: 1.15 $");
 script_name(english:"PHP-Nuke' opendir");
 desc["english"] = "
The remote host has the CGI 'opendir.php' installed. This
CGI allows anyone to read arbitrary files with the privileges
of the web server (usually root or nobody).

Solution : upgrade your version of phpnuke
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to the opendir.php vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 script_dependencie("php_nuke_installed.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
installed = get_kb_item("www/" + port + "/php-nuke");
if ( ! installed ) exit(0);
array = eregmatch(pattern:"(.*) under (.*)", string:installed);
if ( ! array ) exit(0);
url = array[2];


req = http_get(item:string(url, "/opendir.php?/etc/passwd"), port:port);
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL ) exit(0);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:r)){
  	security_hole(port);
	exit(0);
	}
