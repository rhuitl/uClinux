#
# (C) Tenable Network Security

if(description)
{
 script_id(11751);
 script_bugtraq_id(7945);
 script_version ("$Revision: 1.6 $");


 name["english"] = "Dune Web Server Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the Dune Web server
which is older than 0.6.8.

There is a flaw in this software which may be exploited by an attacker
to gain a shell on this host.

Solution : Use another web server or upgrade to Dune 0.6.8
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Dune Overflow";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

if( safe_checks() )
{ 
 banner = get_http_banner(port:port);
 if( banner == NULL ) exit(0);
 
 if(egrep(pattern:"^Server: Dune/0\.([0-5]\.|6\.[0-7]$)", string:banner))
  {
   security_hole(port);
  }
  exit(0);
}


banner = get_http_banner(port:port);
if(!banner)exit(0);
if("Dune/" >!< banner)exit(0);

if(http_is_dead(port:port))exit(0);

req = http_get(item:"/" + crap(51), port:port);
soc = http_open_socket(port);
if(!soc)exit(0);
send(socket:soc, data:req);
r = http_recv(socket:soc);
close(soc);
if(r)
{
 req = http_get(item:"/~" + crap(50), port:port);
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 close(soc);
 if(!r)security_hole(port);
}
