#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21050);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-1158");
  script_bugtraq_id(17043);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"23772");

  script_name(english:"Kerio MailServer IMAP Server Login Command Denial of Service Vulnerability");
  script_summary(english:"Checks how KMS IMAP server responds to login requests");

  desc = "
Synopsis :

The remote IMAP server is prone to denial of service attacks. 

Description :

The remote host is running Kerio MailServer, a commercial mail server
available for Windows, Linux, and Mac OS X platforms. 

The installed version of Kerio MailServer terminates abnormally when
it receives certain malformed IMAP LOGIN commands.  An unauthenticated
remote attacker can exploit this issue to deny access to legitimate
users. 

Note that the application may not terminate immediately but only after
an administrator acknowledges a console message. 

See also : 

http://lists.grok.org.uk/pipermail/full-disclosure/2006-March/043567.html
http://www.kerio.com/kms_history.html

Solution :

Upgrade to Kerio MailServer 6.1.3 Patch 1 or later. 

Risk factor :

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes", "imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
if (get_kb_item("imap/false_imap") || get_kb_item("imap/overflow")) exit(0);


# Make sure it's a potentially-affected version of Kerio.
banner = get_imap_banner(port:port);
if (!banner) exit(0);

pat = ".*OK Kerio MailServer (.+) IMAP.*";
matches = egrep(pattern:pat, string:banner);
ver = NULL;
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    ver = ereg_replace(pattern:pat, replace:"\1", string:match);
    break;
  }
}
if (!ver) exit(0);
iver = split(ver, sep:'.', keep:FALSE);
if (int(iver[0]) > 6) exit(0);
if (int(iver[0]) == 6 && int(iver[1]) > 1) exit(0);
if (int(iver[0]) == 6 && int(iver[1]) == 1 && int(iver[2]) > 3) exit(0);


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s))
{
  close(soc);
  exit(0);
}


# Send a login command.
c = "a001 LOGIN {999999}";
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);


# NB: a patched server responds "+ Go ahead";
#     an unpatched one, "a001 BAD LOGIN Missing user name";
if (strlen(s) && "BAD LOGIN Missing user name" >< s) 
{
  security_note(port);
}
close(soc);
