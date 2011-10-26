#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:038
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20878);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2004-0969");
 
 name["english"] = "MDKSA-2006:038: groff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:038 (groff).



The Trustix Secure Linux team discovered a vulnerability in the groffer
utility, part of the groff package. It created a temporary directory in an
insecure way which allowed for the exploitation of a race condition to create
or overwrite files the privileges of the user invoking groffer. Likewise,
similar temporary file issues were fixed in the pic2graph and eqn2graph
programs which now use mktemp to create temporary files, as discovered by
Javier Fernandez-Sanguino Pena. The updated packages have been patched to
correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:038
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the groff package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"groff-1.19-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-for-man-1.19-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-gxditview-1.19-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-perl-1.19-6.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-1.19-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-for-man-1.19-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-gxditview-1.19-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-perl-1.19-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-1.19.1-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-for-man-1.19.1-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-gxditview-1.19.1-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-perl-1.19.1-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"groff-", release:"MDK10.1")
 || rpm_exists(rpm:"groff-", release:"MDK10.2")
 || rpm_exists(rpm:"groff-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2004-0969", value:TRUE);
}
