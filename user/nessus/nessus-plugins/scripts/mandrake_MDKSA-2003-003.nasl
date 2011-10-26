#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:003
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13988);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2003:003: dhcpcd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:003 (dhcpcd).


A vulnerability was discovered by Simon Kelley in the dhcpcd DHCP client daemon.
dhcpcd has the ability to execute an external script named dhcpcd-.exe when an
IP address is assigned to that network interface. The script sources the file
/var/lib/dhcpcd/dhcpcd-.info which contains shell variables and DHCP assignment
information. The way quotes are handled inside these assignments is flawed, and
a malicious DHCP server can execute arbitrary shell commands on the vulnerable
DHCP client system. This can also be exploited by an attacker able to spoof DHCP
responses.
Mandrake Linux packages contain a sample /etc/dhcpc/dhcpcd.exe file and
encourages all users to upgrade immediately. Please note that when you do
upgrade, you will have to restart the network for the changes to take proper
effect by issuing 'service network restart' as root.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:003
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dhcpcd package";
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
if ( rpm_check( reference:"dhcpcd-1.3.22pl4-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcpcd-1.3.22pl4-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcpcd-1.3.22pl4-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcpcd-1.3.22pl4-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dhcpcd-1.3.22pl4-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
