#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20325);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-3193");
 
 name["english"] = "Fedora Core 3 2005-1170: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1170 (xpdf).

Xpdf is an X Window System based viewer for Portable Document Format
(PDF) files. Xpdf is a small and efficient program which uses
standard X fonts.

Update Information:

Several flaws were discovered in Xpdf. An attacker could
construct a carefully crafted PDF file that could cause xpdf
to crash or possibly execute arbitrary code when opened. The
Common Vulnerabilities and Exposures project assigned the
name CAN-2005-3193 to these issues.

Users of xpdf should upgrade to this updated package, which
contains a patch to resolve these issues.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf package";
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
if ( rpm_check( reference:"xpdf-3.01-0.FC3.4", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"xpdf-", release:"FC3") )
{
 set_kb_item(name:"CAN-2005-3193", value:TRUE);
}
