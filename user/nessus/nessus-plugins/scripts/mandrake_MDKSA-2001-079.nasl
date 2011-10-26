#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:079-2
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14777);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "MDKSA-2001:079-2: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:079-2 (kernel).


Alexander Viro discovered a vulnerability in the devfs implementation that is
shipped with Mandrake Linux 8.1. We are aware of the problem and are currently
working on a solution. As a workaround, until an update becomes available,
please boot with the devfs=nomount option.
Rafal Wojtczuk found a vulnerability in the 2.2.19 and 2.4.11 Linux kernels with
the ptrace code and deeply nested symlinks spending an arbitrary amount of time
in the kernel code. The ptrace vulnerability could be used by local users to
gain root privilege, the symlink vulnerability could result in a local DoS.
There is an additional vulnerability in the kernel's syncookie code which could
potentially allow a remote attacker to guess the cookie and bypass existing
firewall rules. The discovery was found by Manfred Spraul and Andi Kleen.
Update:
The previous advisory was missing the md5sums for the lm_utils packages. The
md5sums are now included in the package list.
NOTE: This update is *not* meant to be done via MandrakeUpdate! You must
download the necessary RPMs and upgrade manually by following these steps:
1. Type: rpm -ivh kernel-[version].i586.rpm 2. Type: mv
kernel-[version].i586.rpm /tmp 3. Type: rpm -Fvh *.rpm 4a. You may wish to edit
/etc/lilo.conf to ensure a new entry is in place. The new kernel will be the
last entry. Change any options you need to change. You will also want to create
a new entry with the initrd and image directives pointing to the old kernel's
vmlinuz and initrd images so you may also boot from the old images if required.
4b. PPC users must execute some additional instructions. First edit
/etc/yaboot.conf and add a new entry for the kernel and change any options that
you need to change. You must also create a new initrd image to enable USB
support for keyboards and mice by typing: mkinitrd --with=usb-ohci
/boot/initrd-2.4.8-31.3mdk 2.4.8-31.3mdk 5a. If you use lilo, type: /sbin/lilo
-v 5b. If you use GRUB, type: sh /boot/grub/install.sh 5c. PPC users must type:
/sbin/ybin -v
You may then reboot and use the new kernel and remove the older kernel when you
are comfortable using the upgraded one.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:079-2
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
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
if ( rpm_check( reference:"kernel-2.4.8-31.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.8-31.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.8-31.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.8-31.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-pcmcia-cs-2.4.8-31.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.8-31.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.8-31.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_utils-2.4.8_2.6.1-31.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_utils-devel-2.4.8_2.6.1-31.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"iptables-1.2.4-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"iptables-ipv6-1.2.4-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.8-34.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.8-34.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.8-34.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.8-34.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-pcmcia-cs-2.4.8-34.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.8-34.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.8-34.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_utils-2.4.8_2.6.1-34.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_utils-devel-2.4.8_2.6.1-34.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"iptables-1.2.4-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"iptables-ipv6-1.2.4-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
