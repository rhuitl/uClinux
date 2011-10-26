#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:021
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13837);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0594", "CVE-2004-0595");
 
 name["english"] = "SUSE-SA:2004:021: php4/mod_php4";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:021 (php4/mod_php4).


PHP is a well known, widely-used scripting language often used within
web server setups.
Stefan Esser found a problem with the 'memory_limit' handling of PHP which
allows remote attackers to execute arbitrary code as the user running
the PHP interpreter. This problem has been fixed. Additionally a
problem within the 'strip_tags' function has been found and fixed which
allowed remote attackers to inject arbitrary tags into certain web
browsers, issuing XSS related attacks.
Since there is no easy workaround except disabling PHP, we recommend
an update for users running the PHP interpreter within the apache
web server.

To be sure the update takes effect you have to restart the apache process
by executing the following command as root:

/usr/sbin/rcapache restart

or if you use the apache2 package

/usr/sbin/rcapache2 restart

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2004_21_php4.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php4/mod_php4 package";
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
if ( rpm_check( reference:"mod_php4-4.1.0-317", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.1.0-317", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.1.0-317", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.2.2-479", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.2.2-479", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.2.2-479", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.3.1-169", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.1-169", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.3.3-177", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.3-177", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.3-177", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.4-43.11", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-servlet-4.3.4-43.11", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-imap-4.3.4-43.11", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-mysql-4.3.4-43.11", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.4-43.11", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-wddx-4.3.4-43.11", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php4-", release:"SUSE8.0")
 || rpm_exists(rpm:"php4-", release:"SUSE8.1")
 || rpm_exists(rpm:"php4-", release:"SUSE8.2")
 || rpm_exists(rpm:"php4-", release:"SUSE9.0")
 || rpm_exists(rpm:"php4-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0594", value:TRUE);
 set_kb_item(name:"CVE-2004-0595", value:TRUE);
}
