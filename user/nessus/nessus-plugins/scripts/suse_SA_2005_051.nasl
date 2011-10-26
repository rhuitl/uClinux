#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:051
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19930);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:051: php4,php5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:051 (php4,php5).


This update fixes the following security issues in the PHP scripting
language.

- Bugs in the PEAR::XML_RPC library allowed remote attackers to pass
arbitrary PHP code to the eval() function (CVE-2005-1921,
CVE-2005-2498).

The Pear::XML_RPC library is not used by default in SUSE Linux, but
might be used by third-party PHP applications.

- An integer overflow bug was found in the PCRE (perl compatible regular
expression) library which could be used by an attacker to potentially
execute code. (CVE-2005-2491)

Please note:

Solution : http://www.suse.de/security/advisories/2005_51_php.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php4,php5 package";
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
if ( rpm_check( reference:"apache2-mod_php4-4.3.3-196", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.3.3-196", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-aolserver-4.3.3-196", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.3-196", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-devel-4.3.3-196", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.3-196", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-exif-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-imap-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-mysql-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-pear-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-recode-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-servlet-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-wddx-4.3.4-43.44", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.8-8.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.8-8.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.8-8.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.8-8.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-exif-4.3.8-8.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.8-8.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-pear-4.3.8-8.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.8-8.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.8-8.14", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.10-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php5-5.0.3-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.10-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.10-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.10-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-exif-4.3.10-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.10-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-pear-4.3.10-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.10-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.10-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-5.0.3-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-devel-5.0.3-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-exif-5.0.3-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-fastcgi-5.0.3-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-pear-5.0.3-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-sysvmsg-5.0.3-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-sysvshm-5.0.3-14.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
