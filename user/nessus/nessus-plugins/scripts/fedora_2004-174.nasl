#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13728);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2004-174: libpng10";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-174 (libpng10).

The libpng10 package contains an old version of libpng, a library of
functions for creating and manipulating PNG (Portable Network Graphics)
image format files.

This package is needed if you want to run binaries that were linked
dynamically
with libpng 1.0.x.

Update Information:

During an audit of Red Hat Linux updates, the Fedora Legacy team found a
security issue in libpng that had not been fixed in Fedora Core. An
attacker could carefully craft a PNG file in such a way that
it would cause an application linked to libpng to crash or potentially
execute arbitrary code when opened by a victim.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-174.shtml
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
if ( rpm_check( reference:"libpng10-1.0.15-4", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng10-devel-1.0.15-4", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng10-debuginfo-1.0.15-4", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
