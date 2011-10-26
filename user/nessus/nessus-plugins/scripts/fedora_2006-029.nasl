#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20410);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3193", "CVE-2005-3626", "CVE-2005-3627");
 
 name["english"] = "Fedora Core 3 2006-029: tetex";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-029 (tetex).

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

Update Information:

Several flaws were discovered in the way teTeX processes PDF
files. An attacker could construct a carefully crafted PDF
file that could cause poppler to crash or possibly execute
arbitrary code when opened.

The Common Vulnerabilities and Exposures project assigned
the names CVE-2005-3624, CVE-2005-3625, CVE-2005-3626, and
CVE-2005-3627 to these issues.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tetex package";
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
if ( rpm_check( reference:"tetex-2.0.2-21.7.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"tetex-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-3193", value:TRUE);
 set_kb_item(name:"CVE-2005-3626", value:TRUE);
 set_kb_item(name:"CVE-2005-3627", value:TRUE);
}
