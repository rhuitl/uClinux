#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14829);
 script_cve_id("CVE-2004-2150");
 script_bugtraq_id(11257);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"10349");
 }
 script_version ("$Revision: 1.4 $");
 name["english"] = "Intellipeer POP3 server user account enumeration";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote POP3 server (probably intellipeer pop3 server) is vulnerable to
an account enumeration issue.

If an attacker attempts to log into the remote host by submitting a bogus
username, then the server will reply with a specific error message if the
account is non-existant, while it will reply with another message if the
account exists.

An attacker may use this flaw to set up a brute force attack against the
remote server to obtain a list of valid user names and accounts.
 
Solution : Upgrade to the newest version of this server or change it
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a flaw in Intellipeer pop3";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
include("pop3_func.inc");

port = get_kb_item("Services/pop3");
if(!port) port = 110;
if ( ! get_port_state(port) ) exit(0);

banner = get_pop3_banner(port:port);
if ( ! banner || "POP3 server ready <" >!< banner ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

banner = recv_line(socket:soc, length:4096);
if ( ! banner ) exit(0);
send(socket:soc, data:'USER nessus' + rand() + '\r\n');
rep = recv_line(socket:soc, length:4096);
if ( ! rep ) exit(0);
if (egrep(pattern:"^-ERR nessus[0-9]* unknown account", string:rep) )
{
 security_warning(port);
}
