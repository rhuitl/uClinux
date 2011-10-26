#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:002
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20472);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3651");
 
 name["english"] = "MDKSA-2006:002: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:002 (ethereal).



Three vulnerabilities were discovered in Ethereal 0.10.13: The IRC and GTP
dissectors could go into an infinite loop. A buffer overflow was discovered by
iDefense in the OSPF dissector. Ethereal has been upgraded to 0.10.14 which
does not suffer from these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:002
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.10.14-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.14-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.14-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.14-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3651", value:TRUE);
}
