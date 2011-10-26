#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13746);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2004-224: abiword";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-224 (abiword).

AbiWord is a cross-platform Open Source word processor. The goal is to make
AbiWord full-featured, and remain lean.

Update Information:

security update


Solution : http://www.fedoranews.org/updates/FEDORA-2004-224.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the abiword package";
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
if ( rpm_check( reference:"abiword-2.0.1-2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"abiword-debuginfo-2.0.1-2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
