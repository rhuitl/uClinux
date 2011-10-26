#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15783);
 script_cve_id("CVE-2004-1533");
 script_bugtraq_id( 11705 );
 script_version ("$Revision: 1.3 $");
 name["english"] = "Digital Mappings Systems POP3 Server overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Digital Mappings Systems POP3 server which is 
vulnerable to a remote buffer overrun vulnerability. An attacker, exploiting 
this flaw, will be able to execute code on remote host by sending a malicious 
username string.

Solution : Ensure that you are running a recent and protected POP3 Server.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks the banner of the remote pop3 server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#
include("pop3_func.inc");

port = get_kb_item("Services/pop3");
if ( ! port ) port = 110;
if ( ! get_port_state(port) ) exit(0);

banner = get_pop3_banner(port:port);
if ( ! banner ) exit(0);
if ( egrep(pattern:"^\+OK.*DMS POP3 Server 1\.([0.4]\.|5\.([0.2]\.|3\.([0-9][^0-9]|[0-1][0-9][^0-9]|2[0-7])))", string:port) )
	security_hole(port);
