#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18163);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1392", "CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043");

 name["english"] = "RHSA-2005-405: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PHP packages that fix various security issues are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  A bug was found in the way PHP processes IFF and JPEG images. It is
  possible to cause PHP to consume CPU resources for a short period of time
  by supplying a carefully crafted IFF or JPEG image. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  names CVE-2005-0524 and CVE-2005-0525 to these issues.

  A buffer overflow bug was also found in the way PHP processes EXIF image
  headers. It is possible for an attacker to construct an image file in such
  a way that it could execute arbitrary instructions when processed by PHP.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-1042 to this issue.

  A denial of service bug was found in the way PHP processes EXIF image
  headers. It is possible for an attacker to cause PHP to enter an infinite
  loop for a short period of time by supplying a carefully crafted image file
  to PHP for processing. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-1043 to this issue.

  Several bug fixes are also included in this update:

  - The security fixes in RHSA-2004-687 to the "unserializer" code introduced
  some performance issues.

  - In the gd extension, the "imagecopymerge" function did not correctly
  handle transparency. The original image was being obscured in the
  resultant image.

  - In the curl extension, safe mode was not enforced for \'file:///\' URL
  lookups (CVE-2004-1392).

  Users of PHP should upgrade to these updated packages, which contain
  backported fixes for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-405.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"php-4.3.2-23.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.2-23.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.2-23.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.2-23.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.2-23.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.2-23.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.2-23.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"php-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1392", value:TRUE);
 set_kb_item(name:"CVE-2005-0524", value:TRUE);
 set_kb_item(name:"CVE-2005-0525", value:TRUE);
 set_kb_item(name:"CVE-2005-1042", value:TRUE);
 set_kb_item(name:"CVE-2005-1043", value:TRUE);
}

set_kb_item(name:"RHSA-2005-405", value:TRUE);
