#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:049
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13952);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:049: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:049 (libpng).


A buffer overflow was found in the in the progressive reader of the PNG library
when the PNG datastream contains more IDAT data than indicated by the IHDR
chunk. These deliberately malformed datastreams would crash applications thus
potentially allowing an attacker to execute malicious code. Many programs make
use of the PNG libraries, including web browsers. This overflow is corrected in
versions 1.0.14 and 1.2.4 of the PNG library.
In order to have the system utilize the upgraded packages after the upgrade, you
must restart all running applications that are linked to libpng. You can obtain
this list by executing 'lsof|grep libpng' or 'fuser -v /usr/lib/libpng.so'.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:049
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libpng package";
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
if ( rpm_check( reference:"libpng-1.0.5-2.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.0.5-2.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.0.8-2.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.0.8-2.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng2-1.0.9-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng2-devel-1.0.9-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng2-1.0.12-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng2-devel-1.0.12-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.4-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.4-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.4-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
