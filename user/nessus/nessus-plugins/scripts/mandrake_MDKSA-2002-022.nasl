#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:022
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13930);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0059");
 
 name["english"] = "MDKSA-2002:022: zlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:022 (zlib).


Matthias Clasen found a security issue in zlib that, when provided with certain
input, causes zlib to free an area of memory twice. This 'double free' bug can
be used to crash any programs that take untrusted compressed input, such as web
browsers, email clients, image viewing software, etc. This vulnerability can be
used to perform Denial of Service attacks and, quite possibly, the execution of
arbitrary code on the affected system.
MandrakeSoft has published two advisories concerning this incident:
MDKSA-2002:022 - zlib MDKSA-2002:023 - packages containing zlib
The second advisory contains additional packages that bring their own copies of
the zlib source, and as such need to be fixed and rebuilt. Updating the zlib
library is sufficient to protect those programs that use the system zlib, but
the packages as noted in MDKSA-2002:023 will need to be updated for those
packages that do not use the system zlib.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:022
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zlib package";
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
if ( rpm_check( reference:"zlib-1.1.3-11.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.1.3-11.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-1.1.3-11.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.1.3-11.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.1.3-16.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.1.3-16.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.1.3-16.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.1.3-16.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"zlib-", release:"MDK7.1")
 || rpm_exists(rpm:"zlib-", release:"MDK7.2")
 || rpm_exists(rpm:"zlib-", release:"MDK8.0")
 || rpm_exists(rpm:"zlib-", release:"MDK8.1") )
{
 set_kb_item(name:"CVE-2002-0059", value:TRUE);
}
