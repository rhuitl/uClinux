#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(15902);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2004-1638");
  script_bugtraq_id(11535);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"11174");
  }

  name["english"] = "MailCarrier SMTP Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of MailCarrier in which the
SMTP service suffers from a buffer overflow vulnerability.  By sending
an overly long EHLO command, a remote attacker can crash the SMTP
service and execute arbitrary code on the target. 

Solution : Upgrade to MailCarrier 3.0.1 or greater.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SMTP Buffer Overflow Vulnerability in MailCarrier";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "SMTP problems";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");

host = get_host_name();
port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if (debug_level) display("debug: searching for SMTP Buffer Overflow vulnerability in MailCarrier on ", host, ":", port, ".\n");

banner = get_smtp_banner(port:port);
if (debug_level) display("debug: banner =>>", banner, "<<.\n");
if ("TABS Mail Server" >!< banner) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

# It's MailCarrier and the port's open so try to overflow the buffer.
#
# nb: this just tries to overflow the buffer and crash the service
#     rather than try to run an exploit, like what muts published
#     as a PoC on 10/23/2004. I've verified that buffer sizes of
#     1032 (from the TABS LABS update alert) and 4095 (from 
#     smtp_overflows.nasl) don't crash the service in 2.5.1 while
#     one of 5100 does so that what I use here.
c = string("EHLO ", crap(5100, "NESSUS"), "\r\n");
if (debug_level) display("debug: C: ", c);
send(socket:soc, data:c);
repeat {
  s = recv_line(socket: soc, length:32768);
  if (debug_level) display("debug: S: ", s);
}
until (s !~ '^[0-9][0-9][0-9]-');
if (!s) {
  close(soc);
  if (debug_level) display("debug: trying to reopen socket.\n");
  soc = open_sock_tcp(port);
  if (!soc) {
    security_hole(port);
    exit(0);
  }
}
send(socket:soc, data:'QUIT\r\n');
s = recv_line(socket:soc, length:32768);
close(soc);
