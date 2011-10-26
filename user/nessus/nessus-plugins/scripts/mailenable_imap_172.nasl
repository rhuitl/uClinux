#
# (C) Tenable Network Security
#


if (description) {
  script_id(20837);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0503");
  script_bugtraq_id(16457);

  script_name(english:"MailEnable IMAP Server EXAMINE Command Denial of Service Vulnerability");
  script_summary(english:"Checks for EXAMINE command denial of service vulnerability in MailEnable IMAP server");

  desc = "
Synopsis :

The remote IMAP server is susceptible to denial of service attacks. 

Description :

The remote host is running MailEnable, a commercial mail server for
Windows. 

According to the version number in its banner, the IMAP server bundled
with the installation of MailEnable Professional on the remote host
may crash when handling certain EXAMINE commands.  An authenticated
attacker may be able to leverage this issue to deny service to users
with a specially-crafted EXAMINE command. 

See also : 

http://www.mailenable.com/professionalhistory.asp

Solution : 

Upgrade to MailEnable Professional 1.72 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service_3digits.nasl");
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


# Check the version number from the SMTP server's banner.
smtp_port = get_kb_item("Services/smtp");
if (!smtp_port) smtp_port = 25;
if (!get_port_state(smtp_port)) exit(0);
if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);

banner = get_smtp_banner(port:smtp_port);
if (
  banner && 
  banner =~ "Mail(Enable| Enable SMTP) Service"
) {
  # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
  #     Professional Edition formats it like "0-1.2-" (for 1.2), and
  #     Enterprise Edition formats it like "0--1.1" (for 1.1).
  ver = eregmatch(pattern:"Version: (0-+)?([0-9][^- ]+)-*", string:banner);
  if (!isnull(ver)) {
    if (ver[1] == NULL) edition = "Standard";
    else if (ver[1] == "0-") edition = "Professional";
    else if (ver[1] == "0--") edition = "Enterprise";
  }
  if (isnull(ver) || isnull(edition)) {
    if (log_verbosity > 1) debug_print("can't determine edition of MailEnable's SMTP connector service!", level:0);
    exit(1);
  }
  ver = ver[2];

  # nb: Professional versions < 1.72 are vulnerable.
  if (edition == "Professional" && ver =~ "^1\.([0-6]|7$|7[01])") {
    security_note(port);
  }
}
