#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15942);
 script_bugtraq_id(11885);
 script_version("$Revision: 1.3 $");

 name["english"] = "Citadel/UX Format String Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Citadel/UX, a BBS software for Unix systems.

There is a format string issue in the remote version of this software
which may be exploited by an attacker to execute arbitrary commands
on the remote host.

Solution : Upgrade to Citadel 6.28 (when available) or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote Citadel server";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 
 script_dependencies("citadel_overflow.nasl");
 script_require_ports("Services/citadel/ux", 504);
 exit(0);
}


port = get_kb_item("Services/citadel/ux");
if ( ! port ) port = 504;

kb = get_kb_item("citadel/" + port + "/version");
if ( ! kb ) exit(0);


version = egrep(pattern:"^Citadel(/UX)? ([0-5]\.*|6\.([0-1][0-9]|2[0-7])[^0-9])", string:kb);

if ( version )
	security_hole(port);

