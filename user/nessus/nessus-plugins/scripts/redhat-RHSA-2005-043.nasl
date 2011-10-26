#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16211);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1235", "CVE-2004-1237", "CVE-2005-0003");

 name["english"] = "RHSA-2005-043:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix several security issues in Red Hat
  Enterprise Linux 3 are now available.

  The Linux kernel handles the basic functions of the operating system.

  This advisory includes fixes for several security issues.


Solution : http://rhn.redhat.com/errata/RHSA-2005-043.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   kernel packages";
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
if ( rpm_check( reference:"kernel-2.4.21-27.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-27.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-27.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-27.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-27.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-27.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-27.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-27.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-27.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-27.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1235", value:TRUE);
 set_kb_item(name:"CVE-2004-1237", value:TRUE);
 set_kb_item(name:"CVE-2005-0003", value:TRUE);
}

set_kb_item(name:"RHSA-2005-043", value:TRUE);
