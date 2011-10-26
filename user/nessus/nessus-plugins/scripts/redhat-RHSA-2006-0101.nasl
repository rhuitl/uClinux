#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20732);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2002-2185", "CVE-2004-1190", "CVE-2005-2458", "CVE-2005-2709", "CVE-2005-2800", "CVE-2005-3044", "CVE-2005-3106", "CVE-2005-3109", "CVE-2005-3276", "CVE-2005-3356", "CVE-2005-3358", "CVE-2005-3784", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4605");

 name["english"] = "RHSA-2006-0101:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 4 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues
  described below:

  - a flaw in network IGMP processing that a allowed a remote user on the
  local network to cause a denial of service (disabling of multicast reports)
  if the system is running multicast applications (CVE-2002-2185, moderate)

  - a flaw which allowed a local user to write to firmware on read-only
  opened /dev/cdrom devices (CVE-2004-1190, moderate)

  - a flaw in gzip/zlib handling internal to the kernel that may allow a
  local user to cause a denial of service (crash) (CVE-2005-2458, low)

  - a flaw in procfs handling during unloading of modules that allowed a
  local user to cause a denial of service or potentially gain privileges
  (CVE-2005-2709, moderate)

  - a flaw in the SCSI procfs interface that allowed a local user to cause a
  denial of service (crash) (CVE-2005-2800, moderate)

  - a flaw in 32-bit-compat handling of the TIOCGDEV ioctl that allowed
  a local user to cause a denial of service (crash) (CVE-2005-3044, important)

  - a race condition when threads share memory mapping that allowed local
  users to cause a denial of service (deadlock) (CVE-2005-3106, important)

  - a flaw when trying to mount a non-hfsplus filesystem using hfsplus that
  allowed local users to cause a denial of service (crash) (CVE-2005-3109,
  moderate)

  - a minor info leak with the get_thread_area() syscall that allowed
  a local user to view uninitialized kernel stack data (CVE-2005-3276, low)

  - a flaw in mq_open system call that allowed a local user to cause a denial
  of service (crash) (CVE-2005-3356, important)

  - a flaw in set_mempolicy that allowed a local user on some 64-bit
  architectures to cause a denial of service (crash) (CVE-2005-3358, important)

  - a flaw in the auto-reap of child processes that allowed a local user to
  cause a denial of service (crash) (CVE-2005-3784, important)

  - a flaw in the IPv6 flowlabel code that allowed a local user to cause a
  denial of service (crash) (CVE-2005-3806, important)

  - a flaw in network ICMP processing that allowed a local user to cause
  a denial of service (memory exhaustion) (CVE-2005-3848, important)

  - a flaw in file lease time-out handling that allowed a local user to cause
  a denial of service (log file overflow) (CVE-2005-3857, moderate)

  - a flaw in network IPv6 xfrm handling that allowed a local user to
  cause a denial of service (memory exhaustion) (CVE-2005-3858, important)

  - a flaw in procfs handling that allowed a local user to read kernel memory
  (CVE-2005-4605, important)

  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0101.html
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
if ( rpm_check( reference:"  kernel-2.6.9-22.0.2.EL.i686.rpm                    a9054fd42cd3105a673f2066caf4de15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-devel-2.6.9-22.0.2.EL.i686.rpm              e3a7fef199a480936043131ca10945e1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-doc-2.6.9-22.0.2.EL.noarch.rpm              bb0a0d5917b0d63d9c683a7f33e519a9", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-2.6.9-22.0.2.EL.i686.rpm            0e26e14f1de7f0e8d39ac918af2a8494", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-devel-2.6.9-22.0.2.EL.i686.rpm      dcb79758906cc2ba683d5b1beadf6db1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.6.9-22.0.2.EL.i686.rpm                e66a773b0425948807df2369519c8416", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-devel-2.6.9-22.0.2.EL.i686.rpm          52aef02b73f55f9a28308713e3cad221", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2002-2185", value:TRUE);
 set_kb_item(name:"CVE-2004-1190", value:TRUE);
 set_kb_item(name:"CVE-2005-2458", value:TRUE);
 set_kb_item(name:"CVE-2005-2709", value:TRUE);
 set_kb_item(name:"CVE-2005-2800", value:TRUE);
 set_kb_item(name:"CVE-2005-3044", value:TRUE);
 set_kb_item(name:"CVE-2005-3106", value:TRUE);
 set_kb_item(name:"CVE-2005-3109", value:TRUE);
 set_kb_item(name:"CVE-2005-3276", value:TRUE);
 set_kb_item(name:"CVE-2005-3356", value:TRUE);
 set_kb_item(name:"CVE-2005-3358", value:TRUE);
 set_kb_item(name:"CVE-2005-3784", value:TRUE);
 set_kb_item(name:"CVE-2005-3806", value:TRUE);
 set_kb_item(name:"CVE-2005-3848", value:TRUE);
 set_kb_item(name:"CVE-2005-3857", value:TRUE);
 set_kb_item(name:"CVE-2005-3858", value:TRUE);
 set_kb_item(name:"CVE-2005-4605", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0101", value:TRUE);
