#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:039
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14023);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(6420);
 script_cve_id("CVE-2002-1380", "CVE-2003-0001", "CVE-2003-0127");
 
 name["english"] = "MDKSA-2003:039: kernel22";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:039 (kernel22).


A number of vulnerabilities have been found in the Linux 2.2 kernel that have
been addressed with the latest 2.2.25 release.
A bug in the kernel module loader code could allow a local user to gain root
privileges. This is done by a local user using ptrace and attaching to a
modprobe process that is spawned if the user triggers the loading of a kernel
module.
A temporary workaround can be used to defend against this flaw. It is possible
to temporarily disable the kmod kernel module loading subsystem in the kernel
after all of the required kernel modules have been loaded. Be sure that you do
not need to load additional kernel modules after implementing this workaround.
To use it, as root execute:
echo /no/such/file >/proc/sys/kernel/modprobe
To automate this, you may wish to add it as the last line of the
/etc/rc.d/rc.local file. You can revert this change by replacing the content
'/sbin/modprobe' in the /proc/sys/kernel/modprobe file. The root user can still
manually load kernel modules with this workaround in place.
As well, multiple ethernet device drivers do not pad frames with null bytes,
which could allow remote attackers to obtain information from previous packets
or kernel memory by using malformed packets.
Finally, the 2.2 kernel allows local users to cause a crash of the host system
by using the mmap() function with a PROT_READ parameter to access non-readable
memory pages through the /proc/pid/mem interface.
All users are encouraged to upgrade to the latest kernel version provided.
For instructions on how to upgrade your kernel in Mandrake Linux, please refer
to:
http://www.mandrakesecure.net/en/kernelupdate.php


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:039
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel22 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"alsa-2.2.25_0.5.11-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"alsa-source-2.2.25_0.5.11-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.2.25-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.2.25-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.2.25-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-pcmcia-cs-2.2.25-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.2.25-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.2.25-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.2.25-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-utils-2.2.25-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"reiserfs-utils-2.2.25_3.5.29-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel22-2.2.25-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel22-smp-2.2.25-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel22-source-2.2.25-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel22-2.2.25-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel22-smp-2.2.25-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel22-source-2.2.25-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel22-", release:"MDK7.2")
 || rpm_exists(rpm:"kernel22-", release:"MDK8.1")
 || rpm_exists(rpm:"kernel22-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-1380", value:TRUE);
 set_kb_item(name:"CVE-2003-0001", value:TRUE);
 set_kb_item(name:"CVE-2003-0127", value:TRUE);
}
