#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20855);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2002-2185", "CVE-2004-1058", "CVE-2004-1073", "CVE-2005-0124", "CVE-2005-0400", "CVE-2005-0815", "CVE-2005-2458", "CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3180", "CVE-2005-3275", "CVE-2005-3806");

 name["english"] = "RHSA-2006-0191:   kernel";
 
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

  - a flaw in network IGMP processing that a allowed a remote user on the
  local network to cause a denial of service (disabling of multicast reports)
  if the system is running multicast applications (CVE-2002-2185, moderate)

  - a race condition that allowed local users to read the environment
  variables of another process (CVE-2004-1058, low)

  - a flaw in the open_exec function of execve that allowed a local user to
  read setuid ELF binaries that should otherwise be protected by standard
  permissions. (CVE-2004-1073, moderate). Red Hat originally reported this
  flaw as being fixed by RHSA-2004:504, but a patch for this issue was
  missing from that update.

  - a flaw in the coda module that allowed a local user to cause a denial of
  service (crash) or possibly gain privileges (CVE-2005-0124, moderate)

  - a potential leak of kernel data from ext2 file system handling
  (CVE-2005-0400, low)

  - flaws in ISO-9660 file system handling that allowed the mounting of
  an invalid image on a CD-ROM to cause a denial of service (crash)
  or potentially execute arbitrary code (CVE-2005-0815, moderate)

  - a flaw in gzip/zlib handling internal to the kernel that may allow a
  local user to cause a denial of service (crash) (CVE-2005-2458, low)

  - a flaw in procfs handling during unloading of modules that allowed a
  local user to cause a denial of service or potentially gain privileges
  (CVE-2005-2709, moderate)

  - a flaw in IPv6 network UDP port hash table lookups that allowed a local
  user to cause a denial of service (hang) (CVE-2005-2973, important)

  - a network buffer info leak using the orinoco driver that allowed a remote
  user to possibly view uninitialized data (CVE-2005-3180, important)

  - a flaw in IPv4 network TCP and UDP netfilter handling that allowed a
  local user to cause a denial of service (crash) (CVE-2005-3275, important)

  - a flaw in the IPv6 flowlabel code that allowed a local user to cause a
  denial of service (crash) (CVE-2005-3806, important)

  The following bugs were also addressed:

  - Handle set_brk() errors in binfmt_elf/aout

  - Correct error handling in shmem_ioctl

  - Correct scsi error return

  - Fix netdump time keeping bug

  - Fix netdump link-down freeze

  - Fix FAT fs deadlock

  All Red Hat Enterprise Linux 2.1 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0191.html
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
if ( rpm_check( reference:"kernel-2.4.9-e.68", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.68", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.68", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.68", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.68", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.68", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.68", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.68", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.68", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-2185", value:TRUE);
 set_kb_item(name:"CVE-2004-1058", value:TRUE);
 set_kb_item(name:"CVE-2004-1073", value:TRUE);
 set_kb_item(name:"CVE-2005-0124", value:TRUE);
 set_kb_item(name:"CVE-2005-0400", value:TRUE);
 set_kb_item(name:"CVE-2005-0815", value:TRUE);
 set_kb_item(name:"CVE-2005-2458", value:TRUE);
 set_kb_item(name:"CVE-2005-2709", value:TRUE);
 set_kb_item(name:"CVE-2005-2973", value:TRUE);
 set_kb_item(name:"CVE-2005-3180", value:TRUE);
 set_kb_item(name:"CVE-2005-3275", value:TRUE);
 set_kb_item(name:"CVE-2005-3806", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0191", value:TRUE);
