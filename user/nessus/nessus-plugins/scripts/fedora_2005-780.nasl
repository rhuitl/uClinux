#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19483);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2095");
 
 name["english"] = "Fedora Core 4 2005-780: squirrelmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-780 (squirrelmail).

SquirrelMail is a standards-based webmail package written in PHP4. It
includes built-in pure PHP support for the IMAP and SMTP protocols, and
all pages render in pure HTML 4.0 (with no Javascript) for maximum
compatibility across browsers.  It has very few requirements and is very
easy to configure and install. SquirrelMail has all the functionality
you would want from an email client, including strong MIME support,
address books, and folder manipulation.

Update Information:

It probably is not a good idea to push a CVS snapshot here,
but upstream screwed up their 1.4.5 release and CVS contains
further fixes like PHP5 related stuff that might make
squirrelmail usable on FC4.  This snapshot worked on my
personal server for the past week, so hopefully it will be
good for everyone else too.

CVE-2005-1769 and CVE-2005-2095 security issues are solved
in this update.

Please report regressions in behavior from our previous
1.4.4 package to Red Hat Bugzilla, product Fedora Core.  All
other squirrelmail bugs please report upstream.


Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_squirrelmail-1.4.6-0.cvs20050812.1.fc4
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squirrelmail package";
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
if ( rpm_check( reference:"squirrelmail-1.4.6-0.cvs20050812.1.fc4", prefix:"squirrelmail-", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"squirrelmail-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2095", value:TRUE);
}
