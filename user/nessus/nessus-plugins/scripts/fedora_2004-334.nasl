#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15475);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(11406);
 script_cve_id("CVE-2004-0803", "CVE-2004-0886");
 
 name["english"] = "Fedora Core 2 2004-334: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-334 (libtiff).

The libtiff package contains a library of functions for manipulating
TIFF (Tagged Image File Format) image format files.  TIFF is a widely
used file format for bitmapped images.  TIFF files usually end in the
.tif extension and they are often quite large.

The libtiff package should be installed if you need to manipulate TIFF
format image files.

Update Information:

The libtiff package contains a library of functions for manipulating
TIFF
(Tagged Image File Format) image format files. TIFF is a widely used
file
format for bitmapped images.

During a source code audit, Chris Evans discovered a number of integer
overflow bugs that affect libtiff. An attacker who has the ability to
trick
a user into opening a malicious TIFF file could cause the application
linked to libtiff to crash or possibly execute arbitrary code. The
Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0886 to this issue.

Additionally, a number of buffer overflow bugs that affect libtiff have
been found. An attacker who has the ability to trick a user into opening
a
malicious TIFF file could cause the application linked to libtiff to
crash
or possibly execute arbitrary code. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-0803 to
this issue.

All users are advised to upgrade to these errata packages, which contain
fixes for these issues.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-334.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff package";
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
if ( rpm_check( reference:"libtiff-3.5.7-20.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.5.7-20.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-debuginfo-3.5.7-20.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"libtiff-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
}
