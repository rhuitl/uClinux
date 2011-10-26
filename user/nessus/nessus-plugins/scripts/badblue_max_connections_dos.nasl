#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14350);
 script_cve_id("CVE-2004-1727");
 script_bugtraq_id(10983);
 script_version ("$Revision: 1.3 $");
 name["english"] = "BadBlue Connections Denial of Service"; 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote BadBlue web server has a bug which may allow attackers to 
prevent it from serving pages properly.

It is possible to disable the remote BadBlue server by issuing approximately
24 concurrent connections to the remote host. An attacker may exploit
this flaw by issuing over 24 connections to the remote server and waiting
indefinitely, thus preventing legitimate users from being able to connect
to this service at all.


Solution : None at this time
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Get the version of the remote badblue server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes", "http_version.nasl");
 exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);

vulnerable = egrep(pattern:"^Server: BadBlue/(1\.|2\.[0-5])", string:banner);
if(vulnerable)security_warning(port);


