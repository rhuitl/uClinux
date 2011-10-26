#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:023
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18057);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0524", "CVE-2005-0525");
 
 name["english"] = "SUSE-SA:2005:023: php4, php5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:023 (php4, php5).


This update fixes the following security issues in the PHP scripting
language:

- A bug in getimagesize() EXIF handling which could lead to a denial of
service attack.

This is tracked by the Mitre CVE IDs  CVE-2005-0524 and CVE-2005-0525.

Additionally this non-security bug was fixed:
- Performance problems of unserialize() caused by previous security
fix to unserialize were fixed.

All SUSE Linux based distributions shipping php4 and php5 were affected.


Solution : http://www.suse.de/security/advisories/2005_23_php.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php4, php5 package";
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
if ( rpm_check( reference:"apache2-mod_php4-4.3.1-176", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.3.1-176", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-aolserver-4.3.1-176", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.1-176", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-devel-4.3.1-176", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.3-187", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.3.3-187", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-aolserver-4.3.3-187", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.3-187", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-devel-4.3.3-187", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.3-187", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-imap-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-mysql-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-recode-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-servlet-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-wddx-4.3.4-43.28", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.8-8.5", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.8-8.5", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.8-8.5", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.8-8.5", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.8-8.5", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.8-8.5", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.8-8.5", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.10-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php5-5.0.3-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.10-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.10-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.10-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.10-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.10-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.10-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-5.0.3-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-devel-5.0.3-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-fastcgi-5.0.3-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-sysvmsg-5.0.3-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-sysvshm-5.0.3-14.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"php4-", release:"SUSE8.2")
 || rpm_exists(rpm:"php4-", release:"SUSE9.0")
 || rpm_exists(rpm:"php4-", release:"SUSE9.1")
 || rpm_exists(rpm:"php4-", release:"SUSE9.2")
 || rpm_exists(rpm:"php4-", release:"SUSE9.3") )
{
 set_kb_item(name:"CVE-2005-0524", value:TRUE);
 set_kb_item(name:"CVE-2005-0525", value:TRUE);
}
