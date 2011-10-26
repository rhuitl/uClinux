#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:044
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13947);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:044: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:044 (squid).


Numerous security problems were fixed in squid-2.4.STABLE7. This releases has
several bugfixes to the Gopher client to correct some security issues. Security
fixes to how squid parses FTP directory listings into HTML have been
implemented. A security fix to how squid forwards proxy authentication
credentials has been applied, as well as the MSNT auth helper has been updated
to fix buffer overflows in the helper. Finally, FTP data channels are now sanity
checked to match the address of the requested FTP server, which prevents
injection of data or theft.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:044
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.4.STABLE7-1.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.4.STABLE7-1.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.4.STABLE7-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.4.STABLE7-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.4.STABLE7-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
