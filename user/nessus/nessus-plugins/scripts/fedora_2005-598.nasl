#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16119);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 3 2005-598: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-598 (libtiff).

The libtiff package contains a library of functions for manipulating
TIFF (Tagged Image File Format) image format files. TIFF is a widely
used file format for bitmapped images. TIFF files usually end in the
.tif extension and they are often quite large.

The libtiff package should be installed if you need to manipulate TIFF
format image files.

Update Information:

The updated libtiff package fixes an integer overflow which could lead
to a buffer overflow in the tiffdump utility.



Solution : http://www.fedoranews.org/blog/index.php?p=257
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff package";
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
if ( rpm_check( reference:"libtiff-3.6.1-9.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
