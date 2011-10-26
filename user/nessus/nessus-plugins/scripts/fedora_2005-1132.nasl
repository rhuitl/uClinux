#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20291);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-3193");
 
 name["english"] = "Fedora Core 4 2005-1132: poppler";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1132 (poppler).

Poppler, a PDF rendering library, it's a fork of the xpdf PDF
viewer developed by Derek Noonburg of Glyph and Cog, LLC.

Update Information:

An attacker could construct a carefully crafted PDF file
that could cause Xpdf to crash or possibly execute arbitrary
code when opened.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the poppler package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"poppler-0.4.1-1.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"poppler-devel-0.4.1-1.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"poppler-", release:"FC4") )
{
 set_kb_item(name:"CAN-2005-3193", value:TRUE);
}
