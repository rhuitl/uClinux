#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14215);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0633", "CVE-2004-0634", "CVE-2004-0635");

 name["english"] = "RHSA-2004-378: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Ethereal packages that fix various security vulnerabilities are now
  available.

  Ethereal is a program for monitoring network traffic.

  The SNMP dissector in Ethereal releases 0.8.15 through 0.10.4 contained a
  memory read flaw. On a system where Ethereal is running, a remote
  attacker could send malicious packets that could cause Ethereal to crash or
  possibly execute arbitrary code. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-0635 to this issue.

  The SMB dissector in Ethereal releases 0.9.15 through 0.10.4 contained a
  null pointer flaw. On a system where Ethereal is running, a remote
  attacker could send malicious packets that could cause Ethereal to crash.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0634 to this issue.

  The iSNS dissector in Ethereal releases 0.10.3 through 0.10.4 contained an
  integer overflow flaw. On a system where Ethereal is running, a remote
  attacker could send malicious packets that could cause Ethereal to crash or
  possibly execute arbitrary code. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-0633 to this issue.

  Users of Ethereal should upgrade to these updated packages, which contain
  a version that is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-378.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.10.5-0.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.5-0.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.5-0.30E.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.5-0.30E.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ethereal-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0633", value:TRUE);
 set_kb_item(name:"CVE-2004-0634", value:TRUE);
 set_kb_item(name:"CVE-2004-0635", value:TRUE);
}
if ( rpm_exists(rpm:"ethereal-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0633", value:TRUE);
 set_kb_item(name:"CVE-2004-0634", value:TRUE);
 set_kb_item(name:"CVE-2004-0635", value:TRUE);
}

set_kb_item(name:"RHSA-2004-378", value:TRUE);
