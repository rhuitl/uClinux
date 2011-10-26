#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12410);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0462", "CVE-2003-0501", "CVE-2003-0550", "CVE-2003-0551", "CVE-2003-0552", "CVE-2003-0619", "CVE-2003-0699");

 name["english"] = "RHSA-2003-239: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that address various security vulnerabilities are
  now available for Red Hat Enterprise Linux.

  The Linux kernel handles the basic functions of the operating system.

  Security issues have been found that affect the versions of the Linux
  kernel shipped with Red Hat Enterprise Linux:

  CVE-2003-0462: Paul Starzetz discovered a file read race condition existing
  in the execve() system call, which could cause a local crash.

  CVE-2003-0501: The /proc filesystem in Linux allows local users to obtain
  sensitive information by opening various entries in /proc/self before
  executing a setuid program. This causes the program to fail to change the
  ownership and permissions of already opened entries.

  CVE-2003-0550: The STP protocol is known to have no security, which could
  allow attackers to alter the bridge topology. STP is now turned off by
  default.

  CVE-2003-0551: STP input processing was lax in its length checking, which
  could lead to a denial of service (DoS).

  CVE-2003-0552: Jerry Kreuscher discovered that the Forwarding table could
  be spoofed by sending forged packets with bogus source addresses the same
  as the local host.

  CVE-2003-0619: An integer signedness error in the decode_fh function of
  nfs3xdr.c allows remote attackers to cause a denial of service (kernel
  panic) via a negative size value within XDR data of an NFSv3 procedure
  call.

  CVE-2003-0699: The C-Media PCI sound driver in Linux kernel versions prior
  to 2.4.21 accesses userspace without using the get_user function, which is
  a potential security hole.

  All users are advised to upgrade to these erratum packages, which contain
  backported security patches correcting these vulnerabilities.




Solution : http://rhn.redhat.com/errata/RHSA-2003-239.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.27", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.27", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.27", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.27", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0462", value:TRUE);
 set_kb_item(name:"CVE-2003-0501", value:TRUE);
 set_kb_item(name:"CVE-2003-0550", value:TRUE);
 set_kb_item(name:"CVE-2003-0551", value:TRUE);
 set_kb_item(name:"CVE-2003-0552", value:TRUE);
 set_kb_item(name:"CVE-2003-0619", value:TRUE);
 set_kb_item(name:"CVE-2003-0699", value:TRUE);
}

set_kb_item(name:"RHSA-2003-239", value:TRUE);
