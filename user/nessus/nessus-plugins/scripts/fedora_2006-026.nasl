#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20407);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3191", "CVE-2005-3626", "CVE-2005-3627");
 
 name["english"] = "Fedora Core 4 2006-026: poppler";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-026 (poppler).

Poppler, a PDF rendering library, it's a fork of the xpdf PDF
viewer developed by Derek Noonburg of Glyph and Cog, LLC.

Update Information:

Chris Evans discovered several flaws in the way poppler
processes PDF files. An attacker could construct a carefully
crafted PDF file that could cause poppler to crash or possibly
execute arbitrary code when opened. The Common
Vulnerabilities and Exposures project assigned the names
CVE-2005-3624, CVE-2005-3625, CVE-2005-3626, and
CVE-2005-3627 to these issues.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the poppler package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"poppler-0.4.4-1.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"poppler-devel-0.4.4-1.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"poppler-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-3191", value:TRUE);
 set_kb_item(name:"CVE-2005-3626", value:TRUE);
 set_kb_item(name:"CVE-2005-3627", value:TRUE);
}
