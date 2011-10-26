#
# (C) Tenable Network Security
#

if(description)
{
 script_id(13856);
 script_cve_id("CVE-2004-1705");
 script_bugtraq_id(10833);
 script_version("$Revision: 1.6 $");

 name["english"] = "Citadel/UX Username overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Citadel/UX, a BBS software for Unix systems.

There is a buffer overflow in the remote version of this software
which may be exploited by an attacker to execute arbitrary commands
on the remote host.

To exploit this flaw, an attacker would need to provide a specially
crafted argument to the USER command.

Solution : Upgrade to Citadel 6.24 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote Citadel server";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/citadel/ux", 504);
 exit(0);
}


port = get_kb_item("Services/citadel/ux");
if ( ! port ) port = 504;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

greetings = recv_line(socket:soc, length:4096);
if ( ! ( greetings =~ "^200.*Citadel(/UX)?.*" ) ) exit(0);

send(socket:soc, data:'INFO\r\n');
for ( i = 0 ; i < 15 ; i ++ )
{
 r = recv_line(socket:soc, length:4096);
 if ( ! r ) break;
 if ( r =~ "^000" ) break;
 data += r;
}

version = egrep(pattern:"^Citadel(/UX)? [0-9.]*", string:data);
if ( version )
{
 version = chomp(version);
 set_kb_item(name:"citadel/" + port + "/version", value:version);
 version = egrep(pattern:"^Citadel(/UX)? ([0-5]\.*|6\.([0-1][0-9]|2[0-3])[^0-9])",
		string:data);

if ( version )
	security_hole(port);
}

