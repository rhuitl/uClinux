#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12451);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0001");

 name["english"] = "RHSA-2004-017: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available as part of ongoing
  support and maintenance of Red Hat Enterprise Linux version
  3. This is the first regular update.

  The Linux kernel handles the basic functions of the operating
  system.

  This is the first regular kernel update for Red Hat Enterprise
  Linux version 3. It contains a new critical security fix, many
  other bug fixes, several device driver updates, and numerous
  performance and scalability enhancements.

  On AMD64 systems, a fix was made to the eflags checking in
  32-bit ptrace emulation that could have allowed local users
  to elevate their privileges. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0001 to this issue.

  Other bug fixes were made in the following kernel areas:
  VM, NPTL, IPC, kernel timer, ext3, NFS, netdump, SCSI,
  ACPI, several device drivers, and machine-dependent
  support for the x86_64, ppc64, and s390 architectures.

  The VM subsystem was improved to better handle extreme
  loads and resource contention (such as might occur during
  heavy database application usage). This has resulted in
  a significantly reduced possibility of hangs, OOM kills,
  and low-mem exhaustion.

  Several NPTL fixes were made to resolve POSIX compliance
  issues concerning process IDs and thread IDs. A section
  in the Release Notes elaborates on a related issue with
  file record locking in multi-threaded applications.

  AMD64 kernels are now configured with NUMA support,
  S390 kernels now have CONFIG_BLK_STATS enabled, and
  DMA capability was restored in the IA64 agpgart driver.

  The following drivers have been upgraded to new versions:

  cmpci ------ 6.36
  e100 ------- 2.3.30-k1
  e1000 ------ 5.2.20-k1
  ips -------- 6.10.52
  megaraid --- v1.18k
  megaraid2 -- v2.00.9

  All Red Hat Enterprise Linux 3 users are advised to upgrade
  their kernels to the packages associated with their machine
  architectures and configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2004-017.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.21-9.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-9.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-9.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0001", value:TRUE);
}

set_kb_item(name:"RHSA-2004-017", value:TRUE);
