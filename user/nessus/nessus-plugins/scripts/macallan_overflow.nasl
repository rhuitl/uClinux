#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16153);
 script_bugtraq_id(12136,12137);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Macallan Mail Solution Multiple HTTP vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Macallan Mail Solution, a mail server 
(POP,SMTP,HTTP) for Windows.

It is reported that Macallan Mail Solution is prone to an HTTP GET buffer 
Overflow vulnerability and to an authentication bypass vulnerability.

An attacker exploiting those flaws may be able to access the administrator
interface, crash the service or execute arbitrary code on the remote host.

Solution : Upgrade to version 4.1.1.0 or later
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Macallan Mail Solution version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

if(!get_port_state(port))exit(0);


foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/%2f/admin.html"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);

 if(egrep(pattern:"<title>Macallan Mail Solutions - Administration</title>", string:res)){
        security_hole(port);
        exit(0);
 }
}
