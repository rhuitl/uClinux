#
# (C) Tenable Network Security
#


if (description) {
  script_id(20394);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0141");
  script_bugtraq_id(16179);

  script_name(english:"Eudora Internet Mail Server < 3.2.8 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Checks for multiple denial of service vulnerabilities in Eudora Internet Mail Server < 3.2.8");
 
  desc = "
Synopsis :

The remote mail server is affected by multiple denial of service flaws.

Description :

The remote host appears to be running Eudora Internet Mail Server, a
mail server for Macs. 

According to its banner, the version of Eudora Internet Mail Server
(EIMS) installed on the remote host is reportedly susceptible to denial
of service attacks involving malformed NTLM authentication requests as
well as corrupted incoming MailX and temporary mail files.  While not
certain, the first issue is likely to be remotely exploitable. 

See also :

http://www.eudora.co.nz/updates.html

Solution :

Upgrade to EIMS version 3.2.8 or later.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/smtp", 25, 106, "Services/pop3", 110, "Services/imap", 143);

  exit(0);
}


include("imap_func.inc");
include("misc_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");


# Do banner checks of various ports.
#
# - SMTP.
port = get_kb_item("Services/smtp");
if (!port) port = 25;
banner = get_smtp_banner(port:port);
if (
  banner && 
  egrep(pattern:"^[0-9][0-9][0-9] .* running Eudora Internet Mail Server.* ([0-2]\.|3.([0-1]\.|2\.[0-7]))", string:banner)
) {
  security_note(port);
  exit(0);
}
# - IMAP.
port = get_kb_item("Services/imap");
if (!port) port = 143;
banner = get_imap_banner(port:port);
if (
  banner && 
  egrep(pattern:"^\* OK .* running Eudora Internet Mail Server.* ([0-2]\.|3.([0-1]\.|2\.[0-7]))", string:banner)
) {
  security_note(port);
  exit(0);
}
# - POP3.
port = get_kb_item("Services/pop3");
if (!port) port = 110;
banner = get_pop3_banner(port:port);
if (
  banner && 
  egrep(pattern:"^\+OK .* running Eudora Internet Mail Server.* ([0-2]\.|3.([0-1]\.|2\.[0-7]))", string:banner)
) {
  security_note(port);
  exit(0);
}
# - ACAP
port = 674;
banner = get_unknown_banner(port:port);
if (
  banner && 
  egrep(pattern:"IMPLEMENTATION Eudora Internet Mail Server.* ([0-2]\.|3.([0-1]\.|2\.[0-7]))", string:banner)
) {
  security_note(port);
  exit(0);
}
# - POP3 password
port = 106;
banner = get_unknown_banner(port:port);
if (
  banner && 
  egrep(pattern:"^[0-9][0-9][0-9] .* running Eudora Internet Mail Server.* ([0-2]\.|3.([0-1]\.|2\.[0-7]))", string:banner)
) {
  security_note(port);
  exit(0);
}
