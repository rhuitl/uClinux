#
# (C) Tenable Network Security
#


if (description) {
  script_id(18058);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-1138");
  script_bugtraq_id(13180);

  name["english"] = "Kerio MailServer Webmail Resource Exhaustion Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote mail server is prone to a denial of service attack.

Description :

According to its banner, the remote host is running a version of Kerio
MailServer prior to 6.0.9.  Such versions may be subject to hangs or
high CPU usage when malformed email messages are viewed through its
WebMail component.  An attacker may be able leverage this issue to deny
service to legitimate users simply by sending a specially-crafted
message and having that message viewed by someone using Kerio WebMail. 

See also :

http://www.kerio.com/kms_history.html

Solution : 

Upgrade to Kerio MailServer 6.0.9 or newer.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:P/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Kerio MailServer < 6.0.9";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smtpserver_detect.nasl", "http_version.nasl");
  script_require_ports("Services/smtp", 25, "Services/www", 80);

  exit(0);
}


include("smtp_func.inc");
include("http_func.inc");


# Try to get the web server's banner.
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (
  banner && 
  egrep(pattern:"^Server: Kerio MailServer ([0-5].*|6\.0\.[0-8])", string:banner)
) {
  security_note(port);
  exit(0);
}


# If that failed, try to get the version from the SMTP server.
port = get_kb_item("Services/smtp");
if (!port) port = 25;
banner = get_smtp_banner(port:port);
if (
  banner && 
  egrep(pattern:"^220 .* Kerio MailServer ([0-5].*|6\.0\.[0-8]) ESMTP ready", string:banner)
) {
  security_note(port);
  exit(0);
}
