#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22054);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3055", "CVE-2005-3273", "CVE-2006-1056", "CVE-2006-1342", "CVE-2006-1343", "CVE-2006-1864", "CVE-2006-2071");

 name["english"] = "RHSA-2006-0579:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix a number of security issues as well as
  other bugs are now available for Red Hat Enterprise Linux 2.1 (32 bit
  architectures)

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues described
  below:

  * a flaw in the USB devio handling of device removal that allowed a local
  user to cause a denial of service (crash) (CVE-2005-3055, moderate)

  * a flaw in ROSE due to missing verification of the ndigis argument of new
  routes (CVE-2005-3273, moderate)

  * an info leak on AMD-based x86 systems that allowed a local user to
  retrieve the floating point exception state of a process run by a different
  user (CVE-2006-1056, important)

  * a minor info leak in socket name handling in the network code
  (CVE-2006-1342, low)

  * a minor info leak in socket option handling in the network code
  (CVE-2006-1343, low)

  * a directory traversal vulnerability in smbfs that allowed a local user to
  escape chroot restrictions for an SMB-mounted filesystem via "..\\"
  sequences (CVE-2006-1864, moderate)

  * a flaw in the mprotect system call that allowed to give write permission
  to a readonly attachment of shared memory (CVE-2006-2071, moderate)

  A performance bug in the NFS implementation that caused clients to
  frequently pause when sending TCP segments during heavy write loads was
  also addressed.

  All Red Hat Enterprise Linux 2.1 users are advised to upgrade their kernels
  to these updated packages, which contain backported fixes to correct these
  issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0579.html
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
if ( rpm_check( reference:"  kernel-2.4.9-e.70.athlon.rpm               a01f8a420613698289df25b15b37c347", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-2.4.9-e.70.i686.rpm                 8cc3614816ac844acbd7a6f5939fcbb8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.70", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-debug-2.4.9-e.70.i686.rpm           31a3335b0203bfa6841751446142dd12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.70", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-enterprise-2.4.9-e.70.i686.rpm      8a3e9b19eea831131c5d983716e71b5d", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.70", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.70.athlon.rpm           909da40944a1664786e7881119735cad", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.70.i686.rpm             783c75ba154ba2892ba824ea90eb3214", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.70", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-summit-2.4.9-e.70.i686.rpm          414c6991ff9f596f4903ab5a74efd47a", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-3055", value:TRUE);
 set_kb_item(name:"CVE-2005-3273", value:TRUE);
 set_kb_item(name:"CVE-2006-1056", value:TRUE);
 set_kb_item(name:"CVE-2006-1342", value:TRUE);
 set_kb_item(name:"CVE-2006-1343", value:TRUE);
 set_kb_item(name:"CVE-2006-1864", value:TRUE);
 set_kb_item(name:"CVE-2006-2071", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0579", value:TRUE);
