#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20104);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3053", "CVE-2005-3108", "CVE-2005-3110", "CVE-2005-3119", "CVE-2005-3180", "CVE-2005-3181");

 name["english"] = "RHSA-2005-808:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix several security issues and a page
  attribute mapping bug are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the
  Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.


  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2005-808.html
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
if ( rpm_check( reference:"kernel-2.6.9-22.0.1.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-22.0.1.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-22.0.1.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-22.0.1.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-22.0.1.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-22.0.1.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3053", value:TRUE);
 set_kb_item(name:"CVE-2005-3108", value:TRUE);
 set_kb_item(name:"CVE-2005-3110", value:TRUE);
 set_kb_item(name:"CVE-2005-3119", value:TRUE);
 set_kb_item(name:"CVE-2005-3180", value:TRUE);
 set_kb_item(name:"CVE-2005-3181", value:TRUE);
}

set_kb_item(name:"RHSA-2005-808", value:TRUE);
