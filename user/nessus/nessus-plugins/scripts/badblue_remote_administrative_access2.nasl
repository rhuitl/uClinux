#
# This script was written by Renaud Deraison
#
#
# XXX Could not reproduce the issue with BadBlue 2.2...
#
# Ref:
#  From: "mattmurphy@kc.rr.com" <mattmurphy@kc.rr.com>
#  To: bugtraq@securityfocus.com
#  Subject: BadBlue Remote Administrative Interface Access Vulnerability
#  Date: Tue, 20 May 2003 16:43:53 -0400


if(description)
{
 script_id(11641);
 script_version ("$Revision: 1.2 $");
 name["english"] = "BadBlue Remote Administrative Interface Access";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote BadBlue web server has a bug in the way its security functions
are performed which may allow attackers to gain administrative control of 
this host.

Solution : Upgrade to BadBlue v 2.3 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Get the version of the remote badblue server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
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

vulnerable = egrep(pattern:"^Server: BadBlue/(1\.|2\.[0-2])", string:banner);
if(vulnerable)security_hole(port);


