#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:098
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18440);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1487", "CVE-2004-1488");
 
 name["english"] = "MDKSA-2005:098: wget";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:098 (wget).



Two vulnerabilities were found in wget. The first is that an HTTP redirect
statement could be used to do a directory traversal and write to files outside
of the current directory. The second is that HTTP redirect statements could be
used to overwrite dot ('.') files, potentially overwriting the user's
configuration files (such as .bashrc, etc.).

The updated packages have been patched to help address these problems by
replacing dangerous directories and filenames containing the dot ('.')
character with an underscore ('_') character.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:098
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wget package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"wget-1.9.1-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.9.1-4.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.9.1-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"wget-", release:"MDK10.0")
 || rpm_exists(rpm:"wget-", release:"MDK10.1")
 || rpm_exists(rpm:"wget-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2004-1487", value:TRUE);
 set_kb_item(name:"CVE-2004-1488", value:TRUE);
}
