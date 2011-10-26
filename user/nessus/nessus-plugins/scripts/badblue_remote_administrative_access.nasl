#
# This script was written by Renaud Deraison
#
#
# Ref:
#  From: "Matthew Murphy" <mattmurphy@kc.rr.com>
#  To: "BugTraq" <bugtraq@securityfocus.com>
#  Subject: BadBlue Remote Administrative Access Vulnerability
#  Date: Sun, 20 Apr 2003 16:28:18 -0500


if(description)
{
 script_id(11554);
 script_bugtraq_id(7387);
 script_version ("$Revision: 1.3 $");
 name["english"] = "BadBlue Administrative Actions Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote BadBlue web server has a bug which may allow attackers to gain
administrative control of this host.

Solution : Upgrade to BadBlue v 2.2 or newer
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

# Technically speaking, version 2.16 is not vulnerable. However since we could
# not test it, we advise everyone to update to 2.2
vulnerable = egrep(pattern:"^Server: BadBlue/(1\.|2\.[0-1])", string:banner);
if(vulnerable)security_hole(port);


