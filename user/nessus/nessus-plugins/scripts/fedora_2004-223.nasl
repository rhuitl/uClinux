#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13749);
 script_bugtraq_id(10724);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0594", "CVE-2004-0595");
 
 name["english"] = "Fedora Core 2 2004-223: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-223 (php).

PHP is an HTML-embedded scripting language. PHP attempts to make it
easy for developers to write dynamically generated webpages. PHP also
offers built-in database integration for several commercial and
non-commercial database management systems, so writing a
database-enabled webpage with PHP is fairly simple. The most common
use of PHP coding is probably as a replacement for CGI scripts. The
mod_php module enables the Apache Web server to understand and process
the embedded PHP language in Web pages.

Update Information:

This update includes the latest release of PHP 4, including fixes for
security issues in memory limit handling (CVE CVE-2004-0594), and the
strip_tags function (CVE CVE-2004-0595).  CVE-2004-0595 is not known
to be exploitable in the default configuration if using httpd 2.0.50,
but can be triggered if the 'register_globals' setting has been
enabled.  CVE-2004-0595 can allow a possible cross-site-scripting
attack with some browsers.

The mbstring extension has been moved into the php-mbstring subpackage
in this update to reduce the overall package size.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-223.shtml
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
if ( rpm_check( reference:"php-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-snmp-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-domxml-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-debuginfo-4.3.8-2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"php-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0594", value:TRUE);
 set_kb_item(name:"CVE-2004-0595", value:TRUE);
}
