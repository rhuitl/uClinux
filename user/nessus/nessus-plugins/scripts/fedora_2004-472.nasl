#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15842);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1036");
 
 name["english"] = "Fedora Core 3 2004-472: squirrelmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-472 (squirrelmail).

SquirrelMail is a standards-based webmail package written in PHP4. It
includes built-in pure PHP support for the IMAP and SMTP protocols,
and
all pages render in pure HTML 4.0 (with no Javascript) for maximum
compatibility across browsers. It has very few requirements and is
very
easy to configure and install. SquirrelMail has all the functionality
you would want from an email client, including strong MIME support,
address books, and folder manipulation.


* Fri Nov 19 2004 Warren Togami 1.4.3a-6.FC3
- FC3

* Fri Nov 19 2004 Warren Togami 1.4.3a-7
- CVE-2004-1036 Cross Site Scripting in encoded text
- #112769 updated splash screens



Solution : http://www.fedoranews.org/blog/index.php?p=112
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squirrelmail package";
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
if ( rpm_check( reference:"squirrelmail-1.4.3a-   Release : 6.FC3", prefix:"squirrelmail-", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"squirrelmail-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-1036", value:TRUE);
}
