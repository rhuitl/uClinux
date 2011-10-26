#
# (C) Tenable Network Security
#


if (description) {
  script_id(18588);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2085");
  script_bugtraq_id(14077);
 
  name["english"] = "Inframail SMTP Server Remote Buffer Overflow Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote SMTP server is vulnerable to a buffer overflow attack. 

Description :

The remote host is running the SMTP server component of Inframail, a
commercial suite of network servers from Infradig Systems. 

According to its banner, the installed version of Inframail suffers
from a buffer overflow vulnerability that arises when the SMTP server
component processes a MAIL FROM command with an excessively long
argument (around 40960 bytes).  Successful exploitation will cause the
service to crash and may allow arbitrary code execution. 

See also : 

http://reedarvin.thearvins.com/20050627-01.html
http://archives.neohapsis.com/archives/fulldisclosure/2005-06/0348.html

Solution : 

Upgrade to Inframail 7.12 or later.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote buffer overflow vulnerability in Inframail SMTP Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


banner = get_smtp_banner(port:port);
if (banner && banner =~ "InfradigServers-MAIL \(([0-5]\..*|6.([0-2].*|3[0-7])) ")
  security_hole(port);
