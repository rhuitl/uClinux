#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20326);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-3193");
 
 name["english"] = "Fedora Core 4 2005-1171: poppler";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1171 (poppler).

Poppler, a PDF rendering library, it's a fork of the xpdf PDF
viewer developed by Derek Noonburg of Glyph and Cog, LLC.

Update Information:

Several more flaws were discovered in Xpdf, which poppler is
based on. An attacker could construct a carefully crafted
PDF file that could cause poppler to crash or possibly
execute arbitrary code when opened. The Common
Vulnerabilities and Exposures project assigned the name
CAN-2005-3193 to these issues.



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
if ( rpm_check( reference:"poppler-0.4.3-1.3", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"poppler-devel-0.4.3-1.3", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"poppler-", release:"FC4") )
{
 set_kb_item(name:"CAN-2005-3193", value:TRUE);
}
