#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21118);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1338");
  script_bugtraq_id(17161);
  script_xref(name:"OSVDB", value:"24014");

  script_name(english:"MailEnable Webmail quoted-printable Denial of Service Vulnerability (2)");
  script_summary(english:"Checks version of MailEnable");

  desc = "
Synopsis :

The remote web server is affected by a denial of service issue. 

Description :

The remote host is running MailEnable, a commercial mail server for
Windows. 

According to its banner, using the webmail service bundled with the
version of MailEnable Enterprise Edition on the remote host to view
specially-formatted quoted-printable messages reportedly can result in
100% CPU utilization. 

See also : 

http://www.mailenable.com/professionalhistory.asp
http://www.mailenable.com/enterprisehistory.asp

Solution : 

Upgrade to MailEnable Professional Edition 1.73 / Enterprise Edition
1.21 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/smtp", 25, "Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("smtp_func.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Make sure banner's from MailEnable.
banner = get_http_banner(port:port);
if (!banner || !egrep(pattern:"^Server: .*MailEnable", string:banner)) exit(0);


# Check the version number from the SMTP server's banner.
smtp_port = get_kb_item("Services/smtp");
if (!smtp_port) smtp_port = 25;
if (!get_port_state(smtp_port)) exit(0);
if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);

banner = get_smtp_banner(port:smtp_port);
if (banner && banner =~ "Mail(Enable| Enable SMTP) Service")
{
  # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
  #     Professional Edition formats it like "0-1.2-" (for 1.2), and
  #     Enterprise Edition formats it like "0--1.1" (for 1.1).
  ver = eregmatch(pattern:"Version: (0-+)?([0-9][^- ]+)-*", string:banner);
  if (!isnull(ver))
  {
    if (ver[1] == NULL) edition = "Standard";
    else if (ver[1] == "0-") edition = "Professional";
    else if (ver[1] == "0--") edition = "Enterprise";
  }
  if (isnull(ver) || isnull(edition)) exit(1);
  ver = ver[2];

  # nb: Professional versions < 1.73 are vulnerable.
  if (edition == "Professional")
  {
    if (ver =~ "^1\.([0-6]|7($|[0-2]))") security_note(port);
  }
  # nb: Enterprise Edition versions < 1.21 are vulnerable.
  else if (edition == "Enterprise")
  {
    if (ver =~ "^1\.([01]([^0-9]|$)|2$)") security_note(port);
  }
}
