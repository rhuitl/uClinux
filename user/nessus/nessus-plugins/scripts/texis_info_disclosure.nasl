#
# This script is (C) Renaud Deraison
#
#
#Ref: (no bid nor cve yet)
# Date: Fri, 14 Mar 2003 14:39:36 -0800
# To: bugtraq@securityfocus.com
# Subject: @(#)Mordred Labs advisory - Texis sensitive information leak
# From: sir.mordred@hushmail.com
#
# This is NOT CVE-2002-0266/BID4035 !




if(description)
{
 script_id(11400);
 script_bugtraq_id(7105);
 script_version ("$Revision: 1.6 $");
 

 name["english"] = "texi.exe information disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CGI 'texis.exe' discloses potentially sensitive information
about the the remote host, such as its internal IP address, the
path to various components (such as cmd.exe) and more information,
when the request /texis.exe/?dump is made.


Solution : None at this time
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for texis.exe";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
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


foreach d ( cgi_dirs() )
{
req = http_get(item:string(d, "/texis.exe/?-dump"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) exit (0);
if("COMPUTERNAME" >< res ) {
  	security_warning(port);
	exit(0);
}
}
