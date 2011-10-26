#
# (C) Tenable Network Security
#


if (description) {
  script_id(17985);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1007");
  script_bugtraq_id(13001);

  name["english"] = "CommuniGate Pro LISTS Module Denial of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote mail server is prone to a denial of service attack. 

Description :

According to its banner, the version of CommuniGate Pro running on the
remote host is prone to an unspecified denial of service vulnerability
arising from a flaw in the LISTS module.  An attacker may be able to
crash the server by sending a malformed multipart message to a list. 

See also :

http://www.stalker.com/CommuniGatePro/HistoryStable.html

Solution : 

Upgrade to CommuniGate Pro 4.3c3 or newer.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for denial of service vulnerability in CommuniGate Pro LISTS module";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


banner = get_smtp_banner(port:port);
if ( banner &&
    egrep(
    string:banner, 
    pattern:"CommuniGate Pro ([0-3]|4\.[0-2]|4\.3([ab][0-9]|c[0-2]))"
  )
) security_note(port);
