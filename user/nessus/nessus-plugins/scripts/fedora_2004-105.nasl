#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13688);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2004-105: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-105 (libpng).

The libpng package contains a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.  PNG
is a bit-mapped graphics format similar to the GIF format.  PNG was
created to replace the GIF format, since GIF uses a patented data
compression algorithm.
 
Libpng should be installed if you need to manipulate PNG format image
files.
 
 
* Mon Apr 19 2004 Matthias Clasen <mclasen redhat com>
 
- fix a possible out-of-bounds read in the error message
  handler. #121229
 
* Tue Mar 02 2004 Elliot Lee <sopwith redhat com>
 
- rebuilt
 
* Fri Feb 27 2004 Mark McLoughlin <markmc redhat com> 2:1.2.2-19
 
- rebuild with changed bits/setjmp.h on ppc
 
* Fri Feb 13 2004 Elliot Lee <sopwith redhat com>
 
- rebuilt
 
 


Solution : http://www.fedoranews.org/updates/FEDORA-2004-105.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libpng package";
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
if ( rpm_check( reference:"libpng-1.2.2-20", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.2-20", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-debuginfo-1.2.2-20", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
