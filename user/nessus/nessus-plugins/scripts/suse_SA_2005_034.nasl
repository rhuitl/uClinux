#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:034
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19243);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:034: opera";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:034 (opera).


The web browser Opera has been updated to version 8.01 to fix various
security-related bugs.

* Fixed XMLHttpRequest redirect vulnerability reported in Secunia
Advisory 15008.
* Fixed cross-site scripting vulnerability reported in Secunia
Advisory 15411.
* Fixed cross-site scripting vulnerability in location header when
automatic redirection is disabled. Vulnerability reported in Secunia
Advisory 15423.
* Fix for variant of window injection vulnerability reported in Secunia
Advisory 13253
* Fixed information disclosure weakness causing file path information
to be sent when using the GET form method. Security Focus Bugtraq
ID #12723.
* Improved accuracy of security bar and modified security icon
behavior: when a certificate is accepted manually after a warning,
the security level of the connection is set to 1.
* Fixed issue with wrong referrers being sent to sites in browsing
history.
* Fixed erroneous display of certificate names containing ampersands.
* Solved problem with collapsed address bars for some pop-ups
missing indication of security level.

These issues are tracked by the Mitre CVE IDs CVE-2005-1475,
CVE-2005-1669 and CVE-2004-1157.


Solution : http://www.suse.de/security/advisories/2005_34_opera.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the opera package";
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
if ( rpm_check( reference:"opera-8.01-4", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.01-4", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.01-1.1", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.01-1.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"opera-8.01-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
