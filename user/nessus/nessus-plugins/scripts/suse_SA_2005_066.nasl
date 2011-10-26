#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:066
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20240);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:066: phpMyAdmin";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:066 (phpMyAdmin).


The MySQL configuration frontend phpMyAdmin was updated to fix
the following security problems which can be remotely exploited:

- Multiple cross-site scripting (XSS) bugs (CVE-2005-3301,
CVE-2005-2869, PMASA-2005-5).

- Multiple file inclusion vulnerabilities that allowed an attacker
to include arbitrary files (CVE-2005-3300, CVE-2005-3301,
PMASA-2005-5).


Solution : http://www.suse.de/security/advisories/2005_66_phpmyadmin.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the phpMyAdmin package";
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
if ( rpm_check( reference:"phpMyAdmin-2.6.3pl1-3.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"phpMyAdmin-2.5.3-41", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"phpMyAdmin-2.5.6-34.11", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"phpMyAdmin-2.6.0-4.11", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"phpMyAdmin-2.6.1pl3-4.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
