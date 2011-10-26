#
# This script is (C) Tenable Network Security
#
#
# Ref:
#  From: "Peter Winter-Smith" <peter4020@hotmail.com>
#  To: vuln@secunia.com
#  Cc: vulnwatch@vulnwatch.org
#  Date: Sat, 24 May 2003 09:15:47 +0000
#  Subject: [VulnWatch] P-News 1.16 Admin Access Vulnerability


if(description)
{
 script_id(11669);
 script_version ("$Revision: 1.8 $");

 name["english"] = "p-news Admin Access";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the p-news bulletin board.

There is a flaw in the version in use which may allow an attacker
who has a 'Member' account to upgrade its privileges to administrator
by supplying a malformed username.

Solution : Delete this CGI
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of p-news.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
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
if(!can_host_php(port:port))exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/p-news.php"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:"<title>P-News ver. (0\.|1\.([0-9][^0-9]|1[0-7]))", string:r))
 {
 	security_warning(port);
	exit(0);
 }
}


dirs = make_list("/news", cgi_dirs());


foreach dir (dirs)
{
 check(loc:dir);
}
