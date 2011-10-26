#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:080
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14329);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2004:080: shorewall";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:080 (shorewall).


The shorewall package has a vulnerability when creating temporary files and
directories, which could allow non-root users to overwrite arbitrary files on
the system. The updated packages are patched to fix the problem.
As well, for Mandrakelinux 10.0, the updated packages have been fixed to start
shorewall after the network, rather than before.
After updating the package, if shorewall was previously running, you may need to
issue a 'service shorewall restart'.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:080
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the shorewall package";
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
if ( rpm_check( reference:"shorewall-2.0.1-3.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shorewall-doc-2.0.1-3.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shorewall-1.3.14-3.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shorewall-doc-1.3.14-3.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shorewall-1.4.8-2.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"shorewall-doc-1.4.8-2.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
