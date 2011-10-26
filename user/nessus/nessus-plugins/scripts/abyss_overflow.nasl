#
# (C) Tenable Network Security
# 


if(description)
{
 script_id(11784);
 script_bugtraq_id(8062, 8064);

 script_version ("$Revision: 1.3 $");
 name["english"] = "Abyss httpd overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Abyss Web server is vulnerable to a buffer overflow
which may be exploited by an attacker to execute arbitrary code on
this host.

Solution : Upgrade to Abyss 1.1.6 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests the version of the remote abyss server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########


include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

#
# I could not really reproduce the issue with 1.1.5, 
# so I'll stick to a banner check instead
#
banner = get_http_banner(port:port);
if(!banner)exit(0);
if(egrep(pattern:"^Server: Abyss/(0\..*|1\.(0\..*|1\.[0-5])) ", string:banner))
       security_hole(port);
exit(0);       
