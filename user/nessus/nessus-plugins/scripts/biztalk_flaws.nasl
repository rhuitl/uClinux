#
# (C) Tenable Network Security
#
#
# Ref:
#  http://www.microsoft.com/technet/security/bulletin/MS03-016.mspx


if (description)
{
 script_id(11638);
 script_bugtraq_id(7469, 7470);
 script_cve_id("CVE-2003-0117", "CVE-2003-0118");
 script_version ("$Revision: 1.10 $");

 script_name(english:"biztalk server flaws");
 desc["english"] = "
The remote host seems to be running Microsoft BizTalk server.

There are two flaws in this software which may allow an attacker
to issue an SQL insertion attack or to execute arbitrary code on
the remote host.

*** Nessus solely relied on the presence of Biztalk to issue
*** this alert, so this might be a false positive

Solution : Make sure you installed the relevant Microsoft Patches available at
http://www.microsoft.com/technet/security/bulletin/MS03-016.mspx

Risk factor : High";



 script_description(english:desc["english"]);
 script_summary(english:"Determines if BizTalk is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs))dirs = make_list();

dirs = make_list(dirs, cgi_dirs());
	
foreach d (dirs)
{
 if ( is_cgi_installed_ka(item:d + "/biztalkhttpreceive.dll", port:port) ) 
 {
 req = http_post(item:d+"/biztalkhttpreceive.dll", port:port);
 idx = stridx(req, string("\r\n\r\n"));
 req = insstr(req, string("\r\nContent-Length: 6\r\n\r\nNESSUS"), idx);

 
 res = http_keepalive_send_recv(port:port, data:req);
 
 if( res == NULL ) exit(0);
 
 #
 # We might do multiple retries as the CGI sometimes stalls
 # when it has received a bad request first.
 # 
 if("HTTP/1.1 100 Continue" >< res ){ 
 	eol = strstr(res, string("\r\n\r\n"));
	end = 1;
	if(eol && strlen(eol) <= 4)end = 3;
 	for(i=0;i<end;i++)
	{
 	if (  "HTTP/1.1 500 Internal Server Error" >< res )
		{ security_hole(port); exit(0); }
	res = http_keepalive_send_recv(port:port, data:req);	
	if(i + 1 < end) sleep(1);	
	}
    }
 }
}
