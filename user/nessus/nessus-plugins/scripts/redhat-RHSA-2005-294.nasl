#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18313);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0757");

 name["english"] = "RHSA-2005-294:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available as part of ongoing support
  and maintenance of Red Hat Enterprise Linux version 3. This is the
  fifth regular update.

  The Linux kernel handles the basic functions of the operating system.

  This is the fifth regular kernel update to Red Hat Enterprise Linux 3.

  New features introduced by this update include:

  - support for 2-TB partitions on block devices
  - support for new disk, network, and USB devices
  - support for clustered APIC mode on AMD64 NUMA systems
  - netdump support on AMD64, Intel EM64T, Itanium, and ppc64 systems
  - diskdump support on sym53c8xx and SATA piix/promise adapters
  - NMI switch support on AMD64 and Intel EM64T systems

  There were many bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement
  in the reliability and scalability of Red Hat Enterprise Linux 3.

  Some key areas affected by these fixes include the kernel\'s networking,
  SATA, TTY, and USB subsystems, as well as the architecture-dependent
  handling under the ia64, ppc64, and x86_64 directories. Scalability
  improvements were made primarily in the memory management and file
  system areas.

  A flaw in offset handling in the xattr file system code backported to
  Red Hat Enterprise Linux 3 was fixed. On 64-bit systems, a user who
  can access an ext3 extended-attribute-enabled file system could cause
  a denial of service (system crash). This issue is rated as having a
  moderate security impact (CVE-2005-0757).

  The following device drivers have been upgraded to new versions:

  3c59x ------ LK1.1.18
  3w-9xxx ---- 2.24.00.011fw (new in Update 5)
  3w-xxxx ---- 1.02.00.037
  8139too ---- (upstream 2.4.29)
  b44 -------- 0.95
  cciss ------ v2.4.54.RH1
  e100 ------- 3.3.6-k2
  e1000 ------ 5.6.10.1-k2
  lpfcdfc ---- 1.0.13 (new in Update 5)
  tg3 -------- 3.22RH

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2005-294.html
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
if ( rpm_check( reference:"  kernel-2.4.21-32.EL.athlon.rpm                        8992dd4ed1397d860a1ae85dfc7b2dbd", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-2.4.21-32.EL.i686.rpm                          7cd1f101f584fc58a804320ab0a55455", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-32.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-32.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-2.4.21-32.EL.i686.rpm                  c7488ce800ccef31568e8b8dda1f405e", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-unsupported-2.4.21-32.EL.i686.rpm      d1479b65b4a6aac62cf97ec4870cf1c1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-32.EL.athlon.rpm                    5d86be94c356e79de1ed971fa4a0ac75", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-32.EL.i686.rpm                      28fac40c22db6db1a7b14a903dc8533b", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-32.EL.athlon.rpm        55fd4b598560907990a420ce99932f57", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-32.EL.i686.rpm          36ffa544956f7a7b98d2f97a31c1fe99", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-32.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-32.EL.athlon.rpm            6110eda2670195aacb0bac8f8e378d33", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-32.EL.i686.rpm              ac92f37920c8e99fbab7b9d36e1ca565", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0757", value:TRUE);
}

set_kb_item(name:"RHSA-2005-294", value:TRUE);
