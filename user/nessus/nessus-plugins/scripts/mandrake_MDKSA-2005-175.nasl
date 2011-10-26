#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:175
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19984);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-3011");
 
 name["english"] = "MDKSA-2005:175: texinfo";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:175 (texinfo).



Frank Lichtenheld has discovered that texindex insecurely creates temporary
files with predictable filenames. This is exploitable if a local attacker were
to create symbolic links in the temporary files directory, pointing to a valid
file on the filesystem. When texindex is executed, the file would be overwitten
with the rights of the user running texindex.

The updated packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:175
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the texinfo package";
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
if ( rpm_check( reference:"info-4.7-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"info-install-4.7-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"texinfo-4.7-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"info-4.8-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"info-install-4.8-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"texinfo-4.8-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"info-4.8-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"info-install-4.8-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"texinfo-4.8-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"texinfo-", release:"MDK10.1")
 || rpm_exists(rpm:"texinfo-", release:"MDK10.2")
 || rpm_exists(rpm:"texinfo-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3011", value:TRUE);
}
