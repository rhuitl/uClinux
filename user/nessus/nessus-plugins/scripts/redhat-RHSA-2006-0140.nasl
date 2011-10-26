#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20751);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2002-2185", "CVE-2004-1057", "CVE-2005-2708", "CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3044", "CVE-2005-3180", "CVE-2005-3275", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858");

 name["english"] = "RHSA-2006-0140:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 3 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues
  described below:

  - a flaw in network IGMP processing that a allowed a remote user on the
  local network to cause a denial of service (disabling of multicast reports)
  if the system is running multicast applications (CVE-2002-2185, moderate)

  - a flaw in remap_page_range() with O_DIRECT writes that allowed a local
  user to cause a denial of service (crash) (CVE-2004-1057, important)

  - a flaw in exec() handling on some 64-bit architectures that allowed
  a local user to cause a denial of service (crash) (CVE-2005-2708, important)

  - a flaw in procfs handling during unloading of modules that allowed a
  local user to cause a denial of service or potentially gain privileges
  (CVE-2005-2709, moderate)

  - a flaw in IPv6 network UDP port hash table lookups that allowed a local
  user to cause a denial of service (hang) (CVE-2005-2973, important)

  - a flaw in 32-bit-compat handling of the TIOCGDEV ioctl that allowed
  a local user to cause a denial of service (crash) (CVE-2005-3044, important)

  - a network buffer info leak using the orinoco driver that allowed
  a remote user to possibly view uninitialized data (CVE-2005-3180, important)

  - a flaw in IPv4 network TCP and UDP netfilter handling that allowed
  a local user to cause a denial of service (crash) (CVE-2005-3275, important)

  - a flaw in the IPv6 flowlabel code that allowed a local user to cause a
  denial of service (crash) (CVE-2005-3806, important)

  - a flaw in network ICMP processing that allowed a local user to cause
  a denial of service (memory exhaustion) (CVE-2005-3848, important)

  - a flaw in file lease time-out handling that allowed a local user to cause
  a denial of service (log file overflow) (CVE-2005-3857, moderate)

  - a flaw in network IPv6 xfrm handling that allowed a local user to
  cause a denial of service (memory exhaustion) (CVE-2005-3858, important)

  All Red Hat Enterprise Linux 3 users are advised to upgrade their kernels
  to the packages associated with their machine architecture and
  configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0140.html
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
if ( rpm_check( reference:"kernel-2.4.21-37.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-37.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-37.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-37.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-37.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-37.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-37.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-37.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-37.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2002-2185", value:TRUE);
 set_kb_item(name:"CVE-2004-1057", value:TRUE);
 set_kb_item(name:"CVE-2005-2708", value:TRUE);
 set_kb_item(name:"CVE-2005-2709", value:TRUE);
 set_kb_item(name:"CVE-2005-2973", value:TRUE);
 set_kb_item(name:"CVE-2005-3044", value:TRUE);
 set_kb_item(name:"CVE-2005-3180", value:TRUE);
 set_kb_item(name:"CVE-2005-3275", value:TRUE);
 set_kb_item(name:"CVE-2005-3806", value:TRUE);
 set_kb_item(name:"CVE-2005-3848", value:TRUE);
 set_kb_item(name:"CVE-2005-3857", value:TRUE);
 set_kb_item(name:"CVE-2005-3858", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0140", value:TRUE);
