#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:032
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13938);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:032: tcpdump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:032 (tcpdump).


Several buffer overflows were found in the tcpdump package by FreeBSD developers
during a code audit, in versions prior to 3.5. However, newer versions of
tcpdump, including 3.6.2, are also vulnerable to another buffer overflow in the
AFS RPC decoding functions, which was discovered by Nick Cleaton. These
vulnerabilities could be used by a remote attacker to crash the the tcpdump
process or possibly even be exploited to execute arbitrary code as the user
running tcpdump, which is usually root.
The newer libpcap 0.6 has also been audited to make it more safe by implementing
better buffer boundary checks in several functions.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:032
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tcpdump package";
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
if ( rpm_check( reference:"libpcap-0.6.2-3.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-devel-0.6.2-3.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-2.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.6.2-3.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-devel-0.6.2-3.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-2.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap0-0.6.2-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap0-devel-0.6.2-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-2.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
