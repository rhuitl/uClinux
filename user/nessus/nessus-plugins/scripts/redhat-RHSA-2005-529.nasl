#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19543);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1056", "CVE-2005-0504", "CVE-2005-0749", "CVE-2005-1263");

 name["english"] = "RHSA-2005-529:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix a number of security issues as well as
  other bugs are now available for Red Hat Enterprise Linux 2.1 (32 bit
  architectures)

  This update has been rated as having important security impact by the
  Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This is a kernel maintenance update to Red Hat Enterprise Linux 2.1.

  The following security issues were corrected:

  A flaw between execve() syscall handling and core dumping of ELF-format
  executables allowed local unprivileged users to cause a denial of
  service (system crash) or possibly gain privileges. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2005-1263
  to this issue.

  A flaw when freeing a pointer in load_elf_library was discovered. A local
  user could potentially use this flaw to cause a denial of service (crash).
  (CVE-2005-0749)

  The Direct Rendering Manager (DRM) driver did not properly check the DMA
  lock, which could allow remote attackers or local users to cause a denial
  of service (X Server crash) or possibly modify the video output.
  (CVE-2004-1056)

  A flaw in the moxa serial driver could allow a local user to perform
  privileged operations such as replacing the firmware. (CVE-2005-0504)

  The following bug fixes were also made:

  - Fix a race condition that can cause a panic in __get_lease()
  - Fix a race condition that can cause a panic when reading /proc/mdstat
  - Fix incorrect ide accounting
  - Prevent non-root users from reloading moxa driver firmware
  - Fix a null-pointer-dereference bug in rpciod
  - Fix legacy-usb handoff for certain IBM platforms
  - Fix a bug that caused busy inodes after unmount
  - Provide an additional fix for a memory leak in scsi_scan_single.
  - Fix a potential kswapd/dquot deadlock.
  - Fix a potential local DoS in shmemfs.
  - Fix a random poolsize vulnerability.

  Red Hat Enterprise Linux 2.1 users are advised to upgrade their kernels to
  the packages associated with their machine configurations as listed in this
  erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2005-529.html
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
if ( rpm_check( reference:"kernel-2.4.9-e.65", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.65", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.65", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.65", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.65", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.65", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.65", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.65", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.65", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1056", value:TRUE);
 set_kb_item(name:"CVE-2005-0504", value:TRUE);
 set_kb_item(name:"CVE-2005-0749", value:TRUE);
 set_kb_item(name:"CVE-2005-1263", value:TRUE);
}

set_kb_item(name:"RHSA-2005-529", value:TRUE);
