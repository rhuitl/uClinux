#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13689);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2004-106: libpng10";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-106 (libpng10).

The libpng10 package contains an old version of libpng, a library of
functions for creating and manipulating PNG (Portable Network Graphics)
image format files.
 
This package is needed if you want to run binaries that were linked
dynamically
with libpng 1.0.x.
 
 
* Mon Apr 19 2004 Matthias Clasen <mclasen redhat com>
 
- fix a possible out-of-bounds read in the error message
  handler. #121229
 
* Tue Mar 02 2004 Elliot Lee <sopwith redhat com>
 
- rebuilt
 
* Fri Feb 13 2004 Elliot Lee <sopwith redhat com>
 
- rebuilt
 
 


Solution : http://www.fedoranews.org/updates/FEDORA-2004-106.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libpng10 package";
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
if ( rpm_check( reference:"libpng10-1.0.13-11", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng10-devel-1.0.13-11", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng10-debuginfo-1.0.13-11", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
