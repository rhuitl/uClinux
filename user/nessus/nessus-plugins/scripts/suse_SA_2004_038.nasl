#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:038
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15552);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(11506);
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-0929");
 
 name["english"] = "SUSE-SA:2004:038: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:038 (libtiff).


libtiff is used by image viewers and web browser to view 'TIFF' images.
These usually open and display those images without querying the user,
making a normal system by default vulnerable to exploits of image
library bugs.

Chris Evans found several security related problems during an audit of
the image handling library libtiff, some related to buffer overflows,
some related to integer overflows and similar. This issue is being
tracked by the CVE ID CVE-2004-0803.

Matthias Claasen found a division by zero in libtiff. This is tracked
by the CVE ID CVE-2004-0804.

Further auditing by Dmitry Levin exposed several additional integer
overflows. These are tracked by the CVE ID CVE-2004-0886.

Additionally, iDEFENSE Security located a buffer overflow in the OJPEG
(old JPEG) handling in the SUSE libtiff package. This was fixed by
disabling the old JPEG support and is tracked by the CVE ID CVE-2004-0929.

SUSE wishes to thank all the reporters, auditors, and programmers
for helping to fix these problems.


Solution : http://www.suse.de/security/2004_38_libtiff.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libtiff-3.5.7-376", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-376", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-376", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.6.1-38.12", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"SUSE8.1")
 || rpm_exists(rpm:"libtiff-", release:"SUSE8.2")
 || rpm_exists(rpm:"libtiff-", release:"SUSE9.0")
 || rpm_exists(rpm:"libtiff-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0804", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
 set_kb_item(name:"CVE-2004-0929", value:TRUE);
}
