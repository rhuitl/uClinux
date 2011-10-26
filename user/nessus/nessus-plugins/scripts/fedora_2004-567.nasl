#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16030);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0959", "CVE-2004-1019", "CVE-2004-1065");
 
 name["english"] = "Fedora Core 2 2004-567: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-567 (php).

PHP is an HTML-embedded scripting language. PHP attempts to make it
easy for developers to write dynamically generated webpages. PHP also
offers built-in database integration for several commercial and
non-commercial database management systems, so writing a
database-enabled webpage with PHP is fairly simple. The most common
use of PHP coding is probably as a replacement for CGI scripts. The
mod_php module enables the Apache Web server to understand and process
the embedded PHP language in Web pages.

Update Information:

This update includes the latest release of PHP 4.3, including fixes
for security issues in the unserializer (CVE CVE-2004-1019), exif
image parsing (CVE CVE-2004-1065), and form upload parsing (CVE
CVE-2004-0958 and CVE-2004-0959).



Solution : http://www.fedoranews.org/blog/index.php?p=220
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php package";
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
if ( rpm_check( reference:"php-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-snmp-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-domxml-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-debuginfo-4.3.10-2.4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"php-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0959", value:TRUE);
 set_kb_item(name:"CVE-2004-1019", value:TRUE);
 set_kb_item(name:"CVE-2004-1065", value:TRUE);
}
