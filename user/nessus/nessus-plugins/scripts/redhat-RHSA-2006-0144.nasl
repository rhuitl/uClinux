#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21089);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2458", "CVE-2005-2801", "CVE-2005-3276");

 name["english"] = "RHSA-2006-0144:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available as part of ongoing support and
  maintenance of Red Hat Enterprise Linux version 3. This is the seventh
  regular update.

  This security advisory has been rated as having moderate security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This is the seventh regular kernel update to Red Hat Enterprise Linux 3.

  New features introduced by this update include:

  - addition of the bnx2, dell_rbu, and megaraid_sas device drivers
  - support for multi-core, multi-threaded Intel Itanium processors
  - upgrade of the SATA subsystem to include ATAPI and SMART support
  - optional tuning via the new numa_memory_allocator, arp_announce,
  and printk_ratelimit sysctls

  There were many bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement in
  the reliability and scalability of Red Hat Enterprise Linux 3.

  There were numerous driver updates and security fixes (elaborated below).
  Other key areas affected by fixes in this update include the networking
  subsystem, the VM subsystem, NPTL handling, autofs4, the USB subsystem,
  CPU enumeration, and 32-bit-exec-mode handling on 64-bit architectures.

  The following device drivers have been upgraded to new versions:

  aacraid -------- 1.1.5-2412
  bnx2 ----------- 1.4.30 (new)
  dell_rbu ------- 2.1 (new)
  e1000 ---------- 6.1.16-k3
  emulex --------- 7.3.3
  fusion --------- 2.06.16.02
  ipmi ----------- 35.11
  megaraid2 ------ v2.10.10.1
  megaraid_sas --- 00.00.02.00 (new)
  tg3 ------------ 3.43RH

  The following security bugs were fixed in this update:

  - a flaw in gzip/zlib handling internal to the kernel that allowed
  a local user to cause a denial of service (crash)
  (CVE-2005-2458,low)

  - a flaw in ext3 EA/ACL handling of attribute sharing that allowed
  a local user to gain privileges (CVE-2005-2801, moderate)

  - a minor info leak with the get_thread_area() syscall that allowed
  a local user to view uninitialized kernel stack data
  (CVE-2005-3276, low)

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0144.html
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
if ( rpm_check( reference:"  kernel-2.4.21-40.EL.athlon.rpm                        14e451648c26efc912a3480708afee6f", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-2.4.21-40.EL.i686.rpm                          67b81d592f5f1d9118c0b4aa98747c90", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-40.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-40.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-2.4.21-40.EL.i686.rpm                  31d4f639796879e49778e1bd01410a44", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-unsupported-2.4.21-40.EL.i686.rpm      719d373fed84087a92493140cd1456f2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-40.EL.athlon.rpm                    e550c1f5343851f18e1e5d7123b16926", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-40.EL.i686.rpm                      8060d4e95fa2b7d5978ac482a8494046", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-40.EL.athlon.rpm        7a1eba47dadfb769ab5dd21e87544dcb", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-40.EL.i686.rpm          2f169daf9e95f6f602415d50a24befb9", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-40.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-40.EL.athlon.rpm            40c1b82a9b3666833ef51f842adce559", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-40.EL.i686.rpm              23e18c3df38f90ea739e96b575c66a2a", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2458", value:TRUE);
 set_kb_item(name:"CVE-2005-2801", value:TRUE);
 set_kb_item(name:"CVE-2005-3276", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0144", value:TRUE);
