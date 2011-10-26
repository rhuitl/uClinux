#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11746);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2001-0938");
 script_bugtraq_id(3608);
 
 name["english"] = "AspUpload vulnerability";
 name["francais"] = "AspUpload vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an ASP script that may allow uploading
of arbitrary files. 

Description :

At least one example script distributed with AspUpload appears to be
installed on the remote web server.  AspUpload is an ASP script that
supports saving and processing files uploading through other web
scripts, and the example script likely contains a flaw that allows an
attacker to upload arbitrary files and store them anywhere on the
affected drive. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=100715294425985&w=2

Solution : 

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the AspUpload software";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 John Lampe",
		francais:"Ce script est Copyright (C) 2003 John Lampe");
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
if(!can_host_asp(port:port))exit(0);

 
foreach dir (cgi_dirs())
{
	req = http_get(item:dir + "/Test11.asp", port:port);
	res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
	if( res == NULL ) exit(0);
	if ("UploadScript11.asp" >< r) 
		{
			security_hole(port);
			exit(0);
		}
}
