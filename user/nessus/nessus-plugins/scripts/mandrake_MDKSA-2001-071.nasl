#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:071
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13886);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:071: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:071 (kernel).


A security hole was found in the earlier Linux 2.4 kernels dealing with iptables
RELATED connection tracking. The iptables ip_conntrack_ftp module, which is used
for stateful inspection of FTP traffic, does not validate parameters passed to
it in an FTP PORT command. Due to this flaw, carefully constructed PORT commands
could open arbitrary holes in the firewall. This hole has been fixed, as well as
a number of other bugs for the 2.4 kernel shipped with Mandrake Linux 8.0
NOTE: This update is *not* meant to be done via MandrakeUpdate! You must
download the necessary RPMs and upgrade manually by following these steps:
1. Type: rpm -ivh kernel-2.4.7-12.3mdk.i586.rpm 2. Type: mv
kernel-2.4.7-12.3mdk.i586.rpm /tmp 3. Type: rpm -Fvh *.rpm 4. You may wish to
edit /etc/lilo.conf to ensure a new entry is in place. The new kernel will be
the last entry. Change any options you need to change. 5. Type: /sbin/lilo -v
You may then reboot and use the nwe kernel and remove the older kernel when you
are comfortable using the upgraded one.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:071
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
if ( rpm_check( reference:"kernel-2.4.7-12.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.7-12.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.7-12.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.7-12.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-pcmcia-cs-2.4.7-12.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.7-12.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.7-12.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_utils-2.4.7_2.6.0-12.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lm_utils-devel-2.4.7_2.6.0-12.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"iptables-1.2.2-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"iptables-ipv6-1.2.2-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
