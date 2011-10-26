#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12089);
 script_bugtraq_id(9790);
 script_version ("$Revision: 1.3 $");

 
 name["english"] = "HotOpenTickets Privilege Escalation";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running HotOpenTickers, a web-based ticketing system.

A vulnerability has been disclosed in all versions of this software, up to
version 02272004_ver2c (not included) which may allow an attacker 
escalate privileges on this server.

Solution : Upgrade to Hot Open Tickets 02272004_ver2c
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for HotOpenTicket";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security"); 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/login.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);

 if ( egrep(pattern:"^hot_[0-9]*2003_ver(1|2[ab])", string:res) )
	{
 	 security_warning(port);
	 exit(0);
	}
}
