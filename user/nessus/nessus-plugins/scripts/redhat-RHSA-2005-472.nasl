#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18389);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0491", "CVE-2005-0176", "CVE-2005-1263");

 name["english"] = "RHSA-2005-472:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 3 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the three security issues
  described below as well as an important fix for a problem that could
  lead to data corruption on x86-architecture SMP systems with greater
  than 4GB of memory through heavy usage of multi-threaded applications.

  A flaw between execve() syscall handling and core dumping of ELF-format
  executables allowed local unprivileged users to cause a denial of
  service (system crash) or possibly gain privileges. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2005-1263
  to this issue.

  A flaw in shared memory locking allowed local unprivileged users to lock
  and unlock regions of shared memory segments they did not own (CVE-2005-0176).

  A flaw in the locking of SysV IPC shared memory regions allowed local
  unprivileged users to bypass their RLIMIT_MEMLOCK resource limit
  (CVE-2004-0491).

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.

  Please also consult the RHEL3 Update 5 advisory RHSA-2005:294 for the
  complete list of features added and bugs fixed in U5, which was released
  only a week prior to this security update.




Solution : http://rhn.redhat.com/errata/RHSA-2005-472.html
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
if ( rpm_check( reference:"kernel-2.4.21-32.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-32.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-32.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-32.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-32.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-32.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-32.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-32.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-32.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0491", value:TRUE);
 set_kb_item(name:"CVE-2005-0176", value:TRUE);
 set_kb_item(name:"CVE-2005-1263", value:TRUE);
}

set_kb_item(name:"RHSA-2005-472", value:TRUE);
