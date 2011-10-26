#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21139);
  script_version("$Revision: 1.1 $");

  script_name(english:"MailEnable POP3 Server APOP Buffer Overflow Vulnerability");
  script_summary(english:"Tries to crash MailEnable POP3 Server");

  desc = "
Synopsis :

The remote POP3 server is affected by a buffer overflow flaw. 

Description :

The remote host is running MailEnable, a commercial mail server for
Windows. 

The POP3 server bundled with the version of MailEnable on the remote
host has a buffer overflow flaw involving the APOP command that can be
exploited remotely by an unauthenticated attacker to crash the
affected service and possibly to execute code remotely. 

See also :

http://forum.mailenable.com/viewtopic.php?t=9845
http://www.mailenable.com/hotfix/default.asp

Solution :

Apply the ME-10012 hotfix or upgrade to MailEnable Standard Edition
1.94 / Professional Edition 1.74 / Enterprise Edition 1.22 or later

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}


include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Make sure banner's from MailEnable.
banner = get_pop3_banner(port:port);
if (!banner || "MailEnable POP3 Server" >!< banner) exit(0);


# Establish a connection
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Make sure APOP is enabled.
s = recv_line(socket:soc, length:1024);
if (strlen(s) && egrep(pattern:"^\+OK .+ MailEnable POP3 Server <.+>", string:s))
{
  # Send a long APOP command - the fix limits the length of the name to 0x4f 
  # so see what happens if we exceed it.
  c = raw_string("APOP ", crap(0x50), " 056924d6c559cca2c64c2a38b030a588\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);

  # Patched / newer versions report "-ERR Bad argument".
  if ("-ERR Unable to log on" >< s) security_hole(port);
}
close(soc);
