#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21728);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(18462);

  script_name(english:"MERCUR Messaging < 2005 SP4 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Checks version of MERCUR Messaging");
 
  desc = "
Synopsis :

The remote mail server is affected by multiple denial of service
flaws. 

Description :

The remote host appears to be running MERCUR Messaging, a commercial
mail server for Windows. 

According to its banner, the version of MERCUR Messaging installed on
the remote host is affected by various denial of service attacks
affecting the SMTP, POP3, and IMAP servers. 

See also :

http://www.atrium-software.com/download/McrReadMe_EN.html

Solution :

Upgrade to MERCUR Messaging version 2005 SP4 or later. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service2.nasl");
  if (NASL_LEVEL >= 3000 )
   script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143, 32000);
 

  exit(0);
}


include("global_settings.inc");
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
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR SMTP Server (v5.00.19".
  if (egrep(pattern:"^[0-9][0-9][0-9] .* MERCUR SMTP Server \(v([0-4]\.|5\.00\.(0[0-9]|1[0-8]))", string:banner))
  {
    security_note(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
# - POP3.
port = get_kb_item("Services/pop3");
if (!port) port = 110;
banner = get_pop3_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR POP3-Server (v5.00.12".
  if (egrep(pattern:"^(\+OK|-ERR) MERCUR POP3-Server \(v([0-4]\.|5\.00\.(0[0-9]|1[01]))", string:banner))
  {
    security_note(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
# - IMAP.
port = get_kb_item("Services/imap");
if (!port) port = 143;
banner = get_imap_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR IMAP4-Server (v5.00.14".
  if (egrep(pattern:"^\* (OK|BAD|NO) MERCUR IMAP4-Server \(v([0-4]\.|5\.00\.(0[0-9]|1[0-3]))", string:banner))
  {
    security_note(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
# - MERCUR Control Service
port = 32000;
banner = get_unknown_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR Control-Service (v5.00.14".
  if (egrep(pattern:"^MERCUR Control-Service \(v([0-4]\.|5\.00\.(0[0-9]|1[0-3]))", string:banner))
  {
    security_note(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
