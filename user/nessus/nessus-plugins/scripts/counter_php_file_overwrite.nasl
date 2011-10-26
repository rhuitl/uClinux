#
# (C) Tenable Network Security
#
#
# Ref: http://www.securitytracker.com/alerts/2003/Mar/1006368.html

if (description)
{
 script_id(11611);
 script_version ("$Revision: 1.6 $");

 script_name(english:"counter.php file overwrite");
 desc["english"] = "
The remote host has the cgi 'counter.php' installed.

This CGI contains a flaw which can be abused by an attacker
to overwrite arbitrary files on the system with the privileges
of the web server.

Solution: Remove this CGI
Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if counter.php is present");
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


dir = make_list(cgi_dirs());
		


foreach d (dir)
{
 url = string(d, '/counter.php?count_log_file=/nessus');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "file(/nessus)" >< buf)
   {
    security_warning(port);
    exit(0);
   }
}
