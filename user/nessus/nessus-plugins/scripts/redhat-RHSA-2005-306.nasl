#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17366);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0008");
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0699", "CVE-2005-0704", "CVE-2005-0705", "CVE-2005-0739");

 name["english"] = "RHSA-2005-306: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages that fix various security vulnerabilities are now
  available.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  The ethereal package is a program for monitoring network traffic.


  A number of security flaws have been discovered in Ethereal. On a system
  where Ethereal is running, a remote attacker could send malicious packets
  to trigger these flaws and cause Ethereal to crash or potentially execute
  arbitrary code.

  A buffer overflow flaw was discovered in the Etheric dissector. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0704 to this issue.

  The GPRS-LLC dissector could crash if the "ignore cipher bit" option was
  set. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0705 to this issue.

  A buffer overflow flaw was discovered in the 3GPP2 A11 dissector. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-0699 to this issue.

  A buffer overflow flaw was discovered in the IAPP dissector. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0739 to this issue.

  Users of ethereal should upgrade to these updated packages, which contain
  version 0.10.10 and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-306.html
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
if ( rpm_check( reference:"ethereal-0.10.10-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.10-1.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.10-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.10-1.EL3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.10-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.10-1.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0699", value:TRUE);
 set_kb_item(name:"CVE-2005-0704", value:TRUE);
 set_kb_item(name:"CVE-2005-0705", value:TRUE);
 set_kb_item(name:"CVE-2005-0739", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0699", value:TRUE);
 set_kb_item(name:"CVE-2005-0704", value:TRUE);
 set_kb_item(name:"CVE-2005-0705", value:TRUE);
 set_kb_item(name:"CVE-2005-0739", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0699", value:TRUE);
 set_kb_item(name:"CVE-2005-0704", value:TRUE);
 set_kb_item(name:"CVE-2005-0705", value:TRUE);
 set_kb_item(name:"CVE-2005-0739", value:TRUE);
}

set_kb_item(name:"RHSA-2005-306", value:TRUE);
