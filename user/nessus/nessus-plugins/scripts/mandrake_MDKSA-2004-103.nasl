#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:103
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14840);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0752");
 
 name["english"] = "MDKSA-2004:103: OpenOffice.org";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:103 (OpenOffice.org).


A vulnerability in OpenOffice.org was reported by pmladek where a local user may
be able to obtain and read documents that belong to another user. The way that
OpenOffice.org created temporary files, which used the user's umask to create
the file, could potentially allow for other users to have read access to the
document (again, dependant upon the user's umask).
The updated packages have been patched to prevent this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:103
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the OpenOffice.org package";
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
if ( rpm_check( reference:"OpenOffice.org-1.1.2-8.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice.org-libs-1.1.2-8.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"OpenOffice.org-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0752", value:TRUE);
}
