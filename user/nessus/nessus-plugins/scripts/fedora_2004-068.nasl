#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13676);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2004-068: netpbm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-068 (netpbm).

The netpbm package contains a library of functions which support
programs for handling various graphics file formats, including .pbm
(portable bitmaps), .pgm (portable graymaps), .pnm (portable anymaps),
.ppm (portable pixmaps) and others.
                                                                                                
Update Information:
                                                                                                
This update of the netpbm package fixes some security holes found by the
Debian group.
                                                                                                
An update to the latest version these packages provide is recommended to
every user of the netpbm programs and toosl.
                                                                                                


Solution : http://www.fedoranews.org/updates/FEDORA-2004-068.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the netpbm package";
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
if ( rpm_check( reference:"netpbm-9.24-12.1.1", prefix:"netpbm-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
