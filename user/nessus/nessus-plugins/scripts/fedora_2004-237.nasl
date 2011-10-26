#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14208);
 script_bugtraq_id(10857);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1363", "CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599");
 
 name["english"] = "Fedora Core 1 2004-237: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-237 (libpng).

The libpng package contains a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.  PNG
is a bit-mapped graphics format similar to the GIF format.  PNG was
created to replace the GIF format, since GIF uses a patented data
compression algorithm.

Libpng should be installed if you need to manipulate PNG format image
files.

several buffer overflows were found in libpng.  An attacker could create 
a carefully crafted PNG file in such a way that it would cause an 
application linked with libpng to execute arbitrary code when the file 
was opened by a victim. 

Solution : http://www.fedoranews.org/updates/FEDORA-2004-237.shtml

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
if ( rpm_check( reference:"libpng-1.2.5-7", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.5-7", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-debuginfo-1.2.5-7", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"libpng-", release:"FC1") )
{
 set_kb_item(name:"CVE-2002-1363", value:TRUE);
 set_kb_item(name:"CVE-2004-0597", value:TRUE);
 set_kb_item(name:"CVE-2004-0598", value:TRUE);
 set_kb_item(name:"CVE-2004-0599", value:TRUE);
}
