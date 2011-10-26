#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:046-3
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13865);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MDKSA-2001:046-3: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:046-3 (kdelibs).


A problem exists with the kdesu component of kdelibs. It created a
world-readable temporary file to exchange authentication information and delete
it shortly after. This can be abused by a local user to gain access to the X
server and could result in a compromise of the account that kdesu would access.
Update:
Konqueror was unable to view manpages. This update corrects the problem and
further corrections to sound are present for those cards that did not work
properly with the previous update.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:046-3
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
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
if ( rpm_check( reference:"arts-2.1.2-4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.1.2-4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.1.2-4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libarts2-2.1.2-4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libarts2-devel-2.1.2-4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
