#
# (C) Tenable Network Security
#
#
# Ref:
#  From: "Peter Winter-Smith" <peter4020@hotmail.com>
#  To: vulnwatch@vulnwatch.org
#  Date: Wed, 14 May 2003 11:19:04 +0000
#  Subject: [VulnWatch] Vulnerability in ' poster version.two'


if (description)
{
 script_id(11629);
 script_version ("$Revision: 1.6 $");

 script_name(english:"Poster version.two privilege escalation");
 desc["english"] = "
The remote host is running 'poster version.two' a news posting
system written in PHP.

There is a flaw in this version which allows new users to enter
a specially crafted name which may allow them to gain administrative
privileges on this installation.

Solution : None at this time - disable this CGI
Risk factor : Medium";


 script_description(english:desc["english"]);
 script_summary(english:"Determines owl is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


dir = make_list("/poster", cgi_dirs());
		

foreach d (dir)
{
 req = http_get(item:d + "/index.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("<title>poster version.two</title>" >< res &&
    "?go=check" >< res &&
    "poster version.two: login" >< res){
    	security_warning(port);
	exit(0);
	}
}
