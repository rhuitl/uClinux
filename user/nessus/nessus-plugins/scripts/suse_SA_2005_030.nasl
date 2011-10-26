#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:030
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18463);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:030: MozillaFirefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:030 (MozillaFirefox).


This update upgrades Mozilla Firefox to version 1.0.4, fixing the
following security problems:

MFSA 2005-42:
A problem in the install confirmation dialog together with a bad fix
for MFSA 2005-41 allowed a remote attacker to execute arbitrary code
with the help of a cross site scripting problem on the Mozilla website.

The Mozilla website has been fixed so this is no real problem anymore.

MFSA 2005-43/CVE-2005-1531:
By causing a frame to navigate back to a previous javascript: URL an
attacker can inject script into the forward site. This site can be
controlled by the attacker allowing them to steal cookies or sensitive
data from that page or to perform actions on behalf of that user.

MFSA 2005-44/CVE-2005-1532:
A variant of MFSA 2005-41 overrides properties on a non-DOM node and
then substitutes that object for one chrome script will access. Most
examples involved the attacker synthesizing an event targeted at a
non-DOM node, and overriding standard DOM node properties such as
type with references to eval() calls or Script() objects.

The MFSA-2005-43 and MFSA-2005-44 flaws also affect the Mozilla
Suite browsers. We are working on updates for those.

Updated packages were already released on May 20th. We wanted to
postpone the advisory until we have fixed packages for the Mozilla
Suite, but these will take some more time.



Solution : http://www.suse.de/security/advisories/2005_30_mozilla_firefox.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the MozillaFirefox package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"MozillaFirebird-1.0.4-2", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.4-0.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.4-1.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.4-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.4-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
