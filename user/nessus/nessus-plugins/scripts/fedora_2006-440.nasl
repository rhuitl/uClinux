#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21273);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 5 2006-440: beagle";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-440 (beagle).

A general infrastructure for making your data easy to find.

Update Information:

This upgrade to 0.2.5 fixes various bugs, including making
the firefox extension work again. It also contains fixes for
a minor security issue where you could inject command line
argument into the indexer helpers.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the beagle package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"beagle-0.2.5-1.fc5.1", release:"FC5") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbeagle-0.2.5-1.fc5.1", release:"FC5") )
{
 security_hole(0);
 exit(0);
}
