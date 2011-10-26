#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:026
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13933);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:026: libsafe";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:026 (libsafe).


Wojciech Purczynski discovered that format string protection in libsafe can be
easily bypassed by using flag characters that are implemented in glibc but are
not implemented in libsafe. It was also discovered that *printf function
wrappers incorrectly parse argument indexing in format strings, making some
incorrect assumptions on the number of arguments and conversion specifications.
These problems were fixed by the libsafe authors in 2.0-12.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:026
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libsafe package";
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
if ( rpm_check( reference:"libsafe-2.0.13-1.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsafe-2.0.13-1.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsafe-2.0.13-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsafe-2.0.13-1.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsafe-2.0.13-1.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
