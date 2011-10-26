#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12477);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0109");

 name["english"] = "RHSA-2004-105: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix a security vulnerability which may allow
  local users to gain root privileges are now available.

  The Linux kernel handles the basic functions of the operating
  system.

  This kernel updates several drivers and fixes a number of bugs, including a
  potential security vulnerability.

  iDefense reported a buffer overflow flaw in the ISO9660 filesystem code.
  An attacker could create a malicious filesystem in such a way that root
  privileges may be obtained if the filesystem is mounted. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0109 to this issue.

  The following drivers were updated:

  LSI megaraid2 v2.10.1.1
  IBM Serveraid v. 6.11.07
  MPT Fusion v.2.05.11.03

  All users are advised to upgrade to these errata packages, which contain
  a backported security patch that corrects this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-105.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel packages";
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.40", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.40", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.40", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.40", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0109", value:TRUE);
}

set_kb_item(name:"RHSA-2004-105", value:TRUE);
