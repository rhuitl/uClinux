#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:002
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16306);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1019", "CVE-2004-1065");
 
 name["english"] = "SUSE-SA:2005:002: php4, mod_php4";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:002 (php4, mod_php4).


PHP is a well known, widely-used scripting language often used within web
server setups.

Stefan Esser and Marcus Boerger found several buffer overflow problems in
the unserializer functions of PHP (CVE-2004-1019) and Ilia Alshanetsky
(CVE-2004-1065) found one in the exif parser. Any of them could allow
remote attackers to execute arbitrary code as the user running the PHP
interpreter.

Additionally a bug where the server would disclose php sourcecode under
some circumstances has been fixed.


Solution : http://www.suse.de/security/advisories/2005_02_php4_mod_php4.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php4, mod_php4 package";
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
if ( rpm_check( reference:"mod_php4-4.2.2-485", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.2.2-485", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.3.1-174", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.1-174", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.1-174", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.3.3-183", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.3-183", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.3-183", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.4-43.22", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.4-43.22", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.4-43.22", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.8-8.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.8-8.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php4-", release:"SUSE8.1")
 || rpm_exists(rpm:"php4-", release:"SUSE8.2")
 || rpm_exists(rpm:"php4-", release:"SUSE9.0")
 || rpm_exists(rpm:"php4-", release:"SUSE9.1")
 || rpm_exists(rpm:"php4-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2004-1019", value:TRUE);
 set_kb_item(name:"CVE-2004-1065", value:TRUE);
}
