#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:066
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13967);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2001-1267", "CVE-2002-0399");
 
 name["english"] = "MDKSA-2002:066: tar";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:066 (tar).


A directory traversal vulnerability was discovered in GNU tar version 1.13.25
and earlier that allows attackers to overwrite arbitrary files during extraction
of the archive by using a '..' (dot dot) in an extracted filename.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:066
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tar package";
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
if ( rpm_check( reference:"tar-1.13.25-6.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tar-1.13.25-6.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tar-1.13.25-6.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tar-1.13.25-6.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tar-1.13.25-6.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tar-1.13.25-6.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"tar-", release:"MDK7.1")
 || rpm_exists(rpm:"tar-", release:"MDK7.2")
 || rpm_exists(rpm:"tar-", release:"MDK8.0")
 || rpm_exists(rpm:"tar-", release:"MDK8.1")
 || rpm_exists(rpm:"tar-", release:"MDK8.2")
 || rpm_exists(rpm:"tar-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2001-1267", value:TRUE);
 set_kb_item(name:"CVE-2002-0399", value:TRUE);
}
