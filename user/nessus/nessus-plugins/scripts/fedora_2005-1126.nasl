#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20278);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-3193", "CVE-2005-3193");
 
 name["english"] = "Fedora Core 4 2005-1126: tetex";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1126 (tetex).

TeTeX is an implementation of TeX for Linux or UNIX systems. TeX takes
a text file and a set of formatting commands as input and creates a
typesetter-independent .dvi (DeVice Independent) file as output.
Usually, TeX is used in conjunction with a higher level formatting
package like LaTeX or PlainTeX, since TeX by itself is not very
user-friendly.

Install tetex if you want to use the TeX text formatting system. If
you are installing tetex, you will also need to install tetex-afm (a
PostScript(TM) font converter for TeX),
tetex-dvips (for converting .dvi files to PostScript format
for printing on PostScript printers), tetex-latex (a higher level
formatting package which provides an easier-to-use interface for TeX),
and tetex-xdvi (for previewing .dvi files in X). Unless you are an
expert at using TeX, you should also install the tetex-doc package,
which includes the documentation for TeX.


The Red Hat tetex package also contains software related to Japanese
support for teTeX such as ptex, what is not a part of teTeX project.

Update Information:

Several flaws were discovered in Xpdf. An attacker could
construct a carefully crafted PDF file that could cause Xpdf
to crash or possibly execute arbitrary code when opened. The
teTeX package contains a copy of the Xpdf code used for
parsing PDF files and is therefore affected by this bug.The
Common Vulnerabilities and Exposures project assigned the
name CAN-2005-3193 to these issues.

Users of teTeX should upgrade to this updated package, which
contains a patch to resolve these issues.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tetex package";
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
if ( rpm_check( reference:"tetex-3.0-7.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-3.0-7.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-3.0-7.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-3.0-7.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-3.0-7.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-3.0-7.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-3.0-7.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-debuginfo-3.0-7.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"tetex-", release:"FC4") )
{
 set_kb_item(name:"CAN-2005-3193", value:TRUE);
 set_kb_item(name:"CVE-2005-3193", value:TRUE);
}
