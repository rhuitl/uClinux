#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16139);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(12240);

 name["english"] = "POP Password Changer Unauthorized Password Change Vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running POP Password Changer, a server to change
POP user's passwords.

According to the version number, the remote software is vulnerable
to an unauthorized access. An attacker, exploiting this flaw, will
be able to change user's password.

Solution : Ensure that you are running a patched or more recent version of this software.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if POP Password Changer is vulnerable to access control bypass.";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);

 script_require_ports(106, "Services/pop3pw");
 script_dependencies('find_service1.nasl', 'find_service_3digits.nasl');
 exit(0);
}

port = get_kb_item("Services/pop3pw");
if (! port) port = 106;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

if (egrep(pattern:"^200 .*poppassd v(0\..*|1\.0) hello, who are you", string:r))
 {
 security_hole(port);
 exit(0);
 }
