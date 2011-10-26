#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22264);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2004-2660", "CVE-2006-1858", "CVE-2006-2444", "CVE-2006-2932", "CVE-2006-2935", "CVE-2006-2936", "CVE-2006-3468", "CVE-2006-3626", "CVE-2006-3745");

 name["english"] = "RHSA-2006-0617:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 4 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues described
  below:

  * a flaw in the proc file system that allowed a local user to use a
  suid-wrapper for scripts to gain root privileges (CVE-2006-3626, Important)

  * a flaw in the SCTP implementation that allowed a local user to cause a
  denial of service (panic) or to possibly gain root privileges
  (CVE-2006-3745, Important)

  * a flaw in NFS exported ext2/ext3 partitions when handling invalid inodes
  that allowed a remote authenticated user to cause a denial of service
  (filesystem panic) (CVE-2006-3468, Important)

  * a flaw in the restore_all code path of the 4/4GB split support of
  non-hugemem kernels that allowed a local user to cause a denial of service
  (panic) (CVE-2006-2932, Important)

  * a flaw in IPv4 netfilter handling for the unlikely use of SNMP NAT
  processing that allowed a remote user to cause a denial of service (crash)
  or potential memory corruption (CVE-2006-2444, Moderate)

  * a flaw in the DVD handling of the CDROM driver that could be used
  together with a custom built USB device to gain root privileges
  (CVE-2006-2935, Moderate)

  * a flaw in the handling of O_DIRECT writes that allowed a local user
  to cause a denial of service (memory consumption) (CVE-2004-2660, Low)

  * a flaw in the SCTP chunk length handling that allowed a remote user to
  cause a denial of service (crash) (CVE-2006-1858, Low)

  * a flaw in the input handling of the ftdi_sio driver that allowed a local
  user to cause a denial of service (memory consumption) (CVE-2006-2936, Low)

  In addition a bugfix was added to enable a clean reboot for the IBM Pizzaro
  machines.

  Red Hat would like to thank Wei Wang of McAfee Avert Labs and Kirill
  Korotaev for reporting issues fixed in this erratum.

  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0617.html
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
if ( rpm_check( reference:"kernel-2.6.9-42.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-42.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-42.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-42.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-42.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-42.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-42.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-2660", value:TRUE);
 set_kb_item(name:"CVE-2006-1858", value:TRUE);
 set_kb_item(name:"CVE-2006-2444", value:TRUE);
 set_kb_item(name:"CVE-2006-2932", value:TRUE);
 set_kb_item(name:"CVE-2006-2935", value:TRUE);
 set_kb_item(name:"CVE-2006-2936", value:TRUE);
 set_kb_item(name:"CVE-2006-3468", value:TRUE);
 set_kb_item(name:"CVE-2006-3626", value:TRUE);
 set_kb_item(name:"CVE-2006-3745", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0617", value:TRUE);
