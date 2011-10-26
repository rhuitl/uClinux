#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:032
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14016);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0085", "CVE-2003-0086");
 
 name["english"] = "MDKSA-2003:032: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:032 (samba).


The SuSE security team, during an audit of the Samba source code, found a flaw
in the main smbd code which could allow an external attacker to remotely and
anonymously gain root privilege on a system running the Samba server. This flaw
exists in all version of Samba 2.x up to and including 2.2.7a. The Samba team
announced 2.2.8 today, however these updated packages include a patch that
corrects this problem.
MandrakeSoft urges all users to upgrade immediately. If you are unable to apply
the updated packages (perhaps due to unavailability on your preferred mirror),
the following steps can be taken to protect an unpatched system:
The 'hosts allow' and 'hosts deny' options in the smb.conf file can be used to
allow access to your Samba server by only selected hosts; for example:

hosts allow = 127.0.0.1 192.168.2.0/24 192.168.3.0/24
hosts deny  = 0.0.0.0/0

This will disallow all connections from machines that are not the localhost or
in the 192.168.2 and 192.168.3 private networks. Alternatively, you can tell
Samba to listen to only specific network interfaces by using the 'interfaces'
and 'bind interfaces only' options:

interfaces = eth1 lo
bind interfaces only = yes

Obviously, use the internal interface for your network and not an external
interface connected to the internet. You may also choose to firewall off some
UDP and TCP ports in addition to the previously mentioned suggestions by
blocking external access to ports 137 and 138 (UDP) and ports 139 and 445 (TCP).
These steps should only be used as a temporary preventative measure and all
users should upgrade as quickly as possible.
Thanks to Sebastian Krahmer and the SuSE security team for performing the audit,
Jeremy Allison for providing the fix, and Andrew Tridgell for providing advice
on how to protect an unpatched Samba system.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:032
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba package";
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
if ( rpm_check( reference:"samba-client-2.2.7a-8.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.7a-8.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-doc-2.2.7a-8.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-server-2.2.7a-8.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.7a-8.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.7a-8.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.7a-8.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-doc-2.2.7a-8.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-server-2.2.7a-8.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.7a-8.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_wins-2.2.7a-8.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.7a-8.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.7a-8.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-doc-2.2.7a-8.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-server-2.2.7a-8.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.7a-8.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-winbind-2.2.7a-8.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nss_wins-2.2.7a-8.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.7a-8.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.7a-8.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-doc-2.2.7a-8.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-server-2.2.7a-8.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.7a-8.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-winbind-2.2.7a-8.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"samba-", release:"MDK8.0")
 || rpm_exists(rpm:"samba-", release:"MDK8.1")
 || rpm_exists(rpm:"samba-", release:"MDK8.2")
 || rpm_exists(rpm:"samba-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0085", value:TRUE);
 set_kb_item(name:"CVE-2003-0086", value:TRUE);
}
