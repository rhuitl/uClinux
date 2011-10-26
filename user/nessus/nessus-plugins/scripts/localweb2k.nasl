# This script was created by Jason Lidow <jason@brandx.net>
# The vulnerability was originally discovered by ts@securityoffice.net 

if(description)

{
	script_id(11005);
	script_bugtraq_id(2268, 4820, 7947);
 	script_cve_id("CVE-2001-0189");
	script_version("$Revision: 1.11 $");
	script_name(english:"LocalWeb2000 remote read");

    script_description(english:"
The remote host is running LocalWeb2000. 

Version 2.1.0 of LocalWeb2000 allows an attacker to view protected 
files on the host's computer. 

Example: http://www.vulnerableserver.com/./protectedfolder/protectedfile.htm

It may also disclose the NetBIOS name of the remote host when
it receives malformed directory requests.

Solution: Contact http://www.intranet-server.co.uk for an update.
	
Risk factor : High");

	script_summary(english:"Checks for LocalWeb2000");

	script_category(ACT_GATHER_INFO);

	script_copyright(english:"This script is Copyright (C) 2002 Jason Lidow <jason@brandx.net>");
	script_family(english:"Remote file access");
	script_dependencie("find_service.nes", "httpver.nasl", "no404.nasl");
	script_require_ports("Services/www", 80);
	exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


banner = get_http_banner(port:port);
  
  

if(banner)
{
	if(egrep(pattern:"^Server: .*LocalWEB2000.*" , string:banner, icase:TRUE))
	{
	security_note(port);
	}
}
