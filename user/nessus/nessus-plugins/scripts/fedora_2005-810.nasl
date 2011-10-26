#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19668);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2498");
 
 name["english"] = "Fedora Core 4 2005-810: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-810 (php).

PHP is an HTML-embedded scripting language. PHP attempts to make it
easy for developers to write dynamically generated webpages. PHP also
offers built-in database integration for several commercial and
non-commercial database management systems, so writing a
database-enabled webpage with PHP is fairly simple. The most common
use of PHP coding is probably as a replacement for CGI scripts. The
mod_php module enables the Apache Web server to understand and process
the embedded PHP language in Web pages.

Update Information:

This update includes the latest upstream version of the PEAR
XML_RPC package, which fixes a security issue in request
parsing in the XML_RPC Server code.  The Common
Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-2498 to this issue.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"php-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-soap-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-snmp-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-xml-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ncurses-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-gd-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-bcmath-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-dba-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-debuginfo-5.0.4-10.4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"php-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2498", value:TRUE);
}
