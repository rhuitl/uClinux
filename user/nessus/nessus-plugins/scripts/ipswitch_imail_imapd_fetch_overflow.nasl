#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21051);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3526");
  script_bugtraq_id(17063);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"23796");

  script_name(english:"Ipswitch IMAP FETCH Command Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of Ipswitch IMAP server");
 
  desc = "
Synopsis :

The remote IMAP server is affected by a buffer overflow vulnerability. 

Description :

The remote host is running Ipswitch Collaboration Suite / IMail Secure
Server / IMail Server, commercial messaging and collaboration suites
for Windows. 

According to its banner, the version of Ipswitch Collaboration Suite /
IMail Secure Server / IMail Server installed on the remote host has a
buffer overflow issue in its IMAP server component.  Using a
specially-crafted FETCH command with excessive data, an authenticated
attacker can crash the IMAP server on the affected host, thereby
denying service to legitimate users, and possibly execute arbitrary
code as LOCAL SYSTEM. 

See also :

http://www.zerodayinitiative.com/advisories/ZDI-06-003.html
http://www.ipswitch.com/support/ics/updates/ics200603prem.asp
http://www.ipswitch.com/support/ics/updates/ics200603stan.asp
http://www.ipswitch.com/support/imail/releases/imsec200603.asp
http://www.ipswitch.com/support/imail/releases/im200603.asp

Solution :

Upgrade to version 2006.03 of the appropriate application. 

Risk factor : 

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes", "imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port) || get_kb_item("imap/false_imap")) exit(0);


# There's a problem if the banner indicates it's < 9.03 (=2006.03).
banner = get_imap_banner(port:port);
if (!banner) exit(0);
if (egrep(pattern:"IMail ([0-8]\.|9.0[0-2])", string:banner)) security_warning(port);
