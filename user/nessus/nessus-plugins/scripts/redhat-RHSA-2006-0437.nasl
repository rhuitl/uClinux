#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22086);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-3055", "CVE-2005-3107", "CVE-2006-0741", "CVE-2006-0742", "CVE-2006-0744", "CVE-2006-1056", "CVE-2006-1242", "CVE-2006-1343", "CVE-2006-2444");

 name["english"] = "RHSA-2006-0437:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available as part of ongoing support and
  maintenance of Red Hat Enterprise Linux version 3. This is the eighth
  regular update.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This is the eighth regular kernel update to Red Hat Enterprise Linux 3.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0437.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   kernel packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.4.21-47.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-47.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-47.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-47.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-47.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-47.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-47.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-47.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-47.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-47.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3055", value:TRUE);
 set_kb_item(name:"CVE-2005-3107", value:TRUE);
 set_kb_item(name:"CVE-2006-0741", value:TRUE);
 set_kb_item(name:"CVE-2006-0742", value:TRUE);
 set_kb_item(name:"CVE-2006-0744", value:TRUE);
 set_kb_item(name:"CVE-2006-1056", value:TRUE);
 set_kb_item(name:"CVE-2006-1242", value:TRUE);
 set_kb_item(name:"CVE-2006-1343", value:TRUE);
 set_kb_item(name:"CVE-2006-2444", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0437", value:TRUE);
