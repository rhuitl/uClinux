#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20139);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-2974");
 
 name["english"] = "Fedora Core 4 2005-1046: libungif";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1046 (libungif).

The libungif package contains a shared library of functions for
loading and saving GIF format image files.  The libungif library can
load any GIF file, but it will save GIFs only in uncompressed format
(i.e., it won't use the patented LZW compression used to save 'normal'
compressed GIF files).

Install the libungif package if you need to manipulate GIF files.  You
should also install the libungif-progs package.

Update Information:

The libungif package contains a shared library of functions
for loading and saving GIF format image files. The libungif
library can load any GIF file, but it will save GIFs only in
uncompressed format; it will not use the patented LZW
compression used to save 'normal' compressed GIF files.

A bug was found in the way libungif handles colormaps. An
attacker could create a GIF file in such a way that could
cause out-of-bounds writes and register corruptions. The
Common Vulnerabilities and Exposures project assigned the
name CAN-2005-2974 to this issue.

All users of libungif should upgrade to the updated
packages, which contain a backported patch to resolve this
issue.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libungif package";
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
if ( rpm_check( reference:"libungif-4.1.3-3.fc4.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-devel-4.1.3-3.fc4.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-progs-4.1.3-3.fc4.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"libungif-", release:"FC4") )
{
 set_kb_item(name:"CAN-2005-2974", value:TRUE);
}
