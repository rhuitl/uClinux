#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:056
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13873);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:056: tcpdump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:056 (tcpdump).


A number of remote buffer overflows were discovered in the tcpdump package that
would allow a remote attack of the local tcpdump process. Intrusion detection
using tcpdump would no longer be useful due to the attack stoping all network
activity on the system. As well, this new version of tcpdump fixes the
vulnerability with decoding AFS ACL packets which would allow a remote attacker
to run arbitrary code on the local system with root privilege.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:056
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
if ( rpm_check( reference:"tcpdump-3.6.2-1.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
