#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15584);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0803", "CVE-2004-0886", "CVE-2004-0888");
 
 name["english"] = "Fedora Core 2 2004-357: kdegraphics";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-357 (kdegraphics).

Graphics applications for the K Desktop Environment.

Includes:
 kdvi (displays TeX .dvi files)
 kfax (displays faxfiles)
 kghostview (displays postscript files)
 kcoloredit (palette editor and color chooser)
 kamera (digital camera support)
 kiconedit (icon editor)
 kpaint (a simple drawing program)
 ksnapshot (screen capture utility)
 kview (image viewer for GIF, JPEG, TIFF, etc.)
 kuickshow (quick picture viewer)
 kooka (scanner application)
 kruler (screen ruler and color measurement tool)

Update Information:

A problem with PDF handling was discovered by Chris Evans, and has
been fixed.  The Common Vulnerabilities and Exposures project
(www.mitre.org) has assigned the name CVE-2004-0888 to this issue.

a number of buffer overflow bugs that affect libtiff have
been found. The kfax application contains a copy of the libtiff code used
for parsing TIFF files and is therefore affected by these bugs. An attacker
who has the ability to trick a user into opening a malicious TIFF file
could cause kfax to crash or possibly execute arbitrary code. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-0803 to this issue.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-357.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdegraphics package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kdegraphics-3.2.2-1.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-3.2.2-1.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-debuginfo-3.2.2-1.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdegraphics-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
}
