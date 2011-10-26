#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21917);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3477");
  script_bugtraq_id(18770);

  script_name(english:"CommuniGate Pro POP3 Empty Inbox Denial of Service Vulnerability");
  script_summary(english:"Checks version of CommuniGate Pro");
 
  desc = "
Synopsis :

The remote mail server is prone to a denial of service attack. 

Description :

According to its banner, the version of CommuniGate Pro running on the
remote host will crash when certain mail clients try to open an empty
mailbox. 

See also :

http://www.stalker.com/CommuniGatePro/History.html

Solution : 

Upgrade to CommuniGate Pro 5.1c2 or newer. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}


include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Check CommuniGate Pro's banner.
banner = get_pop3_banner(port:port);
if (
  banner &&
  "CommuniGate Pro POP3 Server" >< banner &&
  egrep(pattern:"CommuniGate Pro POP3 Server ([0-4]\.|5\.(0[^0-9]|1([ab][0-9]|c1)))", string:banner)
) security_note(port);
