#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17171);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1139", "CVE-2004-1140", "CVE-2004-1141", "CVE-2004-1142", "CVE-2005-0006", "CVE-2005-0007", "CVE-2005-0008", "CVE-2005-0009", "CVE-2005-0010", "CVE-2005-0084");

 name["english"] = "RHSA-2005-037: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages that fix various security vulnerabilities are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  Ethereal is a program for monitoring network traffic.

  A number of security flaws have been discovered in Ethereal. On a system
  where Ethereal is running, a remote attacker could send malicious packets
  to trigger these flaws.

  A flaw in the DICOM dissector could cause a crash. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-1139 to this issue.

  A invalid RTP timestamp could hang Ethereal and create a large temporary
  file, possibly filling available disk space. (CVE-2004-1140)

  The HTTP dissector could access previously-freed memory, causing a crash.
  (CVE-2004-1141)

  An improperly formatted SMB packet could make Ethereal hang, maximizing CPU
  utilization. (CVE-2004-1142)

  The COPS dissector could go into an infinite loop. (CVE-2005-0006)

  The DLSw dissector could cause an assertion, making Ethereal exit
  prematurely. (CVE-2005-0007)

  The DNP dissector could cause memory corruption. (CVE-2005-0008)

  The Gnutella dissector could cause an assertion, making Ethereal exit
  prematurely. (CVE-2005-0009)

  The MMSE dissector could free static memory, causing a crash. (CVE-2005-0010)

  The X11 protocol dissector is vulnerable to a string buffer overflow.
  (CVE-2005-0084)

  Users of Ethereal should upgrade to these updated packages which contain
  version 0.10.9 that is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-037.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.10.9-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.9-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1139", value:TRUE);
 set_kb_item(name:"CVE-2004-1140", value:TRUE);
 set_kb_item(name:"CVE-2004-1141", value:TRUE);
 set_kb_item(name:"CVE-2004-1142", value:TRUE);
 set_kb_item(name:"CVE-2005-0006", value:TRUE);
 set_kb_item(name:"CVE-2005-0007", value:TRUE);
 set_kb_item(name:"CVE-2005-0008", value:TRUE);
 set_kb_item(name:"CVE-2005-0009", value:TRUE);
 set_kb_item(name:"CVE-2005-0010", value:TRUE);
 set_kb_item(name:"CVE-2005-0084", value:TRUE);
}

set_kb_item(name:"RHSA-2005-037", value:TRUE);
