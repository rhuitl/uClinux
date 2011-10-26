#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11567);
 script_version ("$Revision: 1.4 $");
 name["english"] = "CommunigatePro Hijacking";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CommuniGatePro, according to its version number, is vulnerable
to a flaw which may allow an attacker access the mailbox of its victims.

To exploit such a flaw, the attacker needs to send an email to its victim
with a link to an image hosted on a rogue server which will store the Referer
field sent by the user user-agent which contains the credentials used to access
the victim's mailbox.

Solution : Upgrade to CommuniGatePro 4.1b2 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote CommunigatePro web Server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);
if(egrep(pattern:"^Server: CommuniGatePro/([0-3]\.|4\.0|4\.1b1)", string:banner))security_hole(port);

