#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(15855);
  script_version("$Revision: 1.2 $");

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 11/2004)
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"3119");
  }

  name["english"] = "POP3 Unencrypted Cleartext Logins";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running a POP3 daemon that allows cleartext logins over
unencrypted connections.  An attacker can uncover user names and
passwords by sniffing traffic to the POP3 daemon if a less secure
authentication mechanism (eg, USER command, AUTH PLAIN, AUTH LOGIN) is
used. 

Solution : Contact your vendor for a fix or encrypt traffic with SSL /
TLS using stunnel. 

See also : RFC 2222 for infomation about SASL.
           RFC 2595 for information about TLS with POP3.

Risk factor : Low";
  script_description(english:desc["english"]);

  summary["english"] = "Checks if POP3 daemon allows unencrypted cleartext logins";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Misc.";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl", "logins.nasl");
  script_require_ports("Services/pop3", 110);
  script_exclude_keys("pop3/false_pop3");
  script_require_keys("pop3/login", "pop3/password");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# nb: non US ASCII characters in user and password must be 
#     represented in UTF-8.
user = get_kb_item("pop3/login");
pass = get_kb_item("pop3/password");
if (!user || !pass) {
  if (log_verbosity > 1) display("pop3/login and/or pop3/password are empty; ", SCRIPT_NAME, " skipped!\n");
  exit(1);
}

if (get_kb_item("pop3/false_pop3")) exit(0);
port = get_kb_item("Services/pop3");
if (!port) port = 110;
debug_print("checking if POP3 daemon on port ", port, " allows unencrypted cleartext logins.");
if (!get_port_state(port)) exit(0);
# nb: skip it if traffic is encrypted.
encaps = get_kb_item("Transports/TCP/" + port);
if (encaps > 1) exit(0);

# Establish a connection.
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

# Try to determine server's capabilities.
c = "CAPA";
debug_print("C: '", c, "'.");
send(socket:soc, data:string(c, "\r\n"));
caps = "";
s = recv_line(socket:soc, length:1024);
s = chomp(s);
debug_print("S: '", s, "'.");
if (s =~ "^\+OK ") {
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    if (s =~ "^\.$") break;
    caps = string(caps, s, "\n");
  }
}

# Try to determine if problem exists from server's capabilities; 
# otherwise, try to actually log in.
done = 0;
if (egrep(string:caps, pattern:"(SASL (PLAIN|LOGIN)|USER)", icase:TRUE)) {
  security_note(port);
  done = 1;
}
if (!done) {
  # nb: there's no way to distinguish between a bad username / password
  #     combination and disabled unencrypted logins. This makes it 
  #     important to configure the scan with valid POP3 username /
  #     password info.

  # - try the PLAIN SASL mechanism.
  c = "AUTH PLAIN";
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
      m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
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

  # If that didn't work, try USER command.
  if (isnull(resp)) {
    c = string("USER ", user);
    debug_print("C: '", c, "'.");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      debug_print("S: '", s, "'.");
      m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }

    if (resp && resp =~ "OK") {
      c = string("PASS ", pass);
      debug_print("C: '", c, "'.");
      send(socket:soc, data:string(c, "\r\n"));
      while (s = recv_line(socket:soc, length:1024)) {
        s = chomp(s);
        debug_print("S: '", s, "'.");
        m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
        resp = "";
      }
    }
  }

  # If successful, unencrypted logins are possible.
  if (resp && resp =~ "OK") security_note(port);
}

# Logout.
c = "QUIT";
debug_print("C: '", c, "'.");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  debug_print("S: '", s, "'.");
  m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);

