#
# (C) Tenable Network Security
#

if(description)
{
 script_id(13842);
 script_bugtraq_id(10774);
 script_version ("$Revision: 1.4 $");

 
 name["english"] = "Mensajeitor Tag Board Admin Bypass";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mensajeitor Tag Board.

There is a vulnerability in this software which may allow an attacker to
post arbitrary messages on the remote board by passing the admin authentication.

An attacker may exploit this flaw to polute the remote board.

Solution : None at this time
Risk factor : Low";

 script_description(english:desc["english"]);
 summary["english"] = "Mensajeitor test";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);


foreach dir ( cgi_dirs() )
{
 res = http_keepalive_send_recv(data:http_get(item:dir + "/mensajeitor.php", port:port), port:port);
 if ( res == NULL ) exit(0);
 if ( "Mensajeitor" >< res && egrep(pattern:"<title>Mensajeitor v1\.([0-7]\.|8\.[0-9])</title>", string:res))
	{
	 security_warning(port);
	 exit(0);
	}

}
