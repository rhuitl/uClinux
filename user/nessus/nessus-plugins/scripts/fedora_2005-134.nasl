#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16356);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0888");
 
 name["english"] = "Fedora Core 2 2005-134: kdegraphics";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-134 (kdegraphics).

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


* Wed Feb 09 2005 Than Ngo
7:3.2.2-1.4

- More fixing of CVE-2004-0888 patch (bug #135393)



Solution : http://www.fedoranews.org/blog/index.php?p=384
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdegraphics package";
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
if ( rpm_check( reference:"kdegraphics-3.2.2-1.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-3.2.2-1.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-debuginfo-3.2.2-1.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdegraphics-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
}
