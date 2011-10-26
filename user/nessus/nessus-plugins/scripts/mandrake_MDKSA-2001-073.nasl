#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:073-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13888);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MDKSA-2001:073-1: xloadimage";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:073-1 (xloadimage).


A buffer overflow exists in xli due to missing boundary checks. This could be
triggered by an external attacker to execute commands on the victim's machine.
An exploit is publically available. xli is an image viewer that is used by
Netscape's plugger to display TIFF, PNG, and Sun-Raster images.
Update:
The xloadimage package uses the same code as xli and is likewise vulnerable. An
update is provided for xloadimage which was only provided with Linux-Mandrake
7.2.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:073-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xloadimage package";
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
if ( rpm_check( reference:"xli-1.16-4.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xli-1.16-7.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xloadimage-4.1-6.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xli-1.17.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
