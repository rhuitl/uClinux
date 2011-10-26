#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12509);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0495", "CVE-2004-0554");

 name["english"] = "RHSA-2004-260: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages for Red Hat Enterprise Linux 2.1 that fix security
  vulnerabilities are now available.

  The Linux kernel handles the basic functions of the operating system.

  A flaw was found in Linux kernel versions 2.4 and 2.6 for x86 and x86_64
  that allowed local users to cause a denial of service (system crash) by
  triggering a signal handler with a certain sequence of fsave and frstor
  instructions. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0554 to this issue.

  Enhancements were committed to the 2.6 kernel by Al Viro which enabled the
  Sparse source code checking tool to check for a certain class of kernel
  bugs. A subset of these fixes also applies to various drivers in the 2.4
  kernel. These flaws could lead to privilege escalation or access to kernel
  memory. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2004-0495 to these issues.

  All Red Hat Enterprise Linux 2.1 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum. These packages contain
  backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-260.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.41", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.41", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.41", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.41", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0495", value:TRUE);
 set_kb_item(name:"CVE-2004-0554", value:TRUE);
}

set_kb_item(name:"RHSA-2004-260", value:TRUE);
