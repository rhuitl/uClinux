#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(15856);
  script_version("$Revision: 1.1 $");

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 11/2004)
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"3119");
  }

  name["english"] = "IMAP Unencrypted Cleartext Logins";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running an IMAP daemon that allows cleartext logins over
unencrypted connections.  An attacker can uncover user names and
passwords by sniffing traffic to the IMAP daemon if a less secure
authentication mechanism (eg, LOGIN command, AUTH=PLAIN, AUTH=LOGIN)
is used.

Solution : Contact your vendor for a fix or encrypt traffic with SSL /
TLS using stunnel. 

See also : RFC 2222 for infomation about SASL.
           RFC 2595 for information about TLS with IMAP.

Risk factor : Low";
  script_description(english:desc["english"]);

  summary["english"] = "Checks if IMAP daemon allows unencrypted cleartext logins";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Misc.";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# nb: non US ASCII characters in user and password must be 
#     represented in UTF-8.
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  if (log_verbosity > 1) display("imap/login and/or imap/password are empty; ", SCRIPT_NAME, " skipped!\n");
  exit(1);
}

port = get_kb_item("Services/imap");
if (!port) port = 143;
debug_print("checking if IMAP daemon on port ", port, " allows unencrypted cleartext logins.");
if (!get_port_state(port)) exit(0);
# nb: skip it if traffic is encrypted.
encaps = get_kb_item("Transports/TCP/" + port);
if (encaps > 1) exit(0);

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
debug_print("S: '", s, "'.");

# Determine server's capabilities.
#
# - look for it in the server's banner.
pat = "CAPABILITY ([^]]+)";
matches = egrep(string:s, pattern:pat, icase:TRUE);
foreach match (split(matches)) {
  match = chomp(match);
  debug_print("grepping >>", match, "<< for =>>", pat, "<<");
  caps = eregmatch(pattern:pat, string:match, icase:TRUE);
  if (!isnull(caps)) caps = caps[1];
}
# - try the CAPABILITY command.
if (isnull(caps)) {
  ++tag;
  c = string("a", string(tag), " CAPABILITY");
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    pat = "^* CAPABILITY (.+)";
    debug_print("grepping '", s, "' for '", pat, "'.");
    caps = eregmatch(pattern:pat, string:s, icase:TRUE);
    if (!isnull(caps)) caps = caps[1];
  }
}

# Try to determine if problem exists from server's capabilities; 
# otherwise, try to actually log in.
done = 0;
if (!isnull(caps)) {
  if (caps =~ "AUTH=(PLAIN|LOGIN)") {
    security_note(port);
    done = 1;
  }
  else if (caps =~ "LOGINDISABLED") {
    # there's no problem.
    done = 1;
  }
}
if (!done) {
  # nb: there's no way to distinguish between a bad username / password
  #     combination and disabled unencrypted logins. This makes it 
  #     important to configure the scan with valid IMAP username /
  #     password info.

  # - try the PLAIN SASL mechanism.
  ++tag;
  c = string("a", string(tag), ' AUTHENTICATE "PLAIN"');
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);
  debug_print("S: '", s, "'.");
  if (s =~ "^\+") {
    c = base64(str:raw_string(0, user, 0, pass));
    debug_print("C: '", c, "'.");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      debug_print("S: '", s, "'.");
      m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }
  }
  # nb: the obsolete LOGIN SASL mechanism is also dangerous. Since the
  #     PLAIN mechanism is required to be supported, though, I won't
  #     bother to check for the LOGIN mechanism.

  # If that didn't work, try LOGIN command.
  if (isnull(resp)) {
    ++tag;
    c = string("a", string(tag), " LOGIN ", user, " ", pass);
    debug_print("C: '", c, "'.");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      debug_print("S: '", s, "'.");
      m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }
  }

  # If successful, unencrypted logins are possible.
  if (resp && resp =~ "OK") security_note(port);
}

# Logout.
++tag;
c = string("a", string(tag), " LOGOUT");
debug_print("C: '", c, "'.");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  debug_print("S: '", s, "'.");
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
