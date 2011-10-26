#
# (C) Tenable Network Security
#


if (description) {
  script_id(20320);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2923");
  script_bugtraq_id(15753);

  script_name(english:"Ipswitch IMAPD LIST Command Denial of Service Vulnerability");
  script_summary(english:"Checks for LIST command denial of service vulnerability in Ipswitch IMAPD");
 
  desc = "
Synopsis :

The remote IMAP server is affected by a denial of service
vulnerability. 

Description :

The remote host is running Ipswitch Collaboration Suite or IMail
Server, commercial messaging and collaboration suites for Windows. 

The version of Ipswitch Collaboration Suite / IMail server installed
on the remote host contains an IMAP server that suffers from a denial
of service flaw.  Using a specially crafted LIST command of around
8000 bytes, an authenticated attacker can crash the IMAP server on the
affected host, thereby denying service to legitimate users. 

See also : 

http://www.idefense.com/application/poi/display?id=347&type=vulnerabilities
http://www.ipswitch.com/support/ics/updates/ics202.asp
http://www.ipswitch.com/support/imail/releases/imail_professional/im822.asp

Solution : 

Upgrade to Ipswitch Collaboration Suite 2.02 / IMail 8.22 or later. 

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:N/I:N/A:C/B:A)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("find_service.nes", "imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


# There's a problem if the banner indicates it's < 8.22.
banner = get_imap_banner(port:port);
if (
  banner && 
  egrep(pattern:"IMail ([0-7]\.|8.([01]|2[01])([^0-9]|$))", string:banner)
) {
  security_warning(port);
  exit(0);
}
