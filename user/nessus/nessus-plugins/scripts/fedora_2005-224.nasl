#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18315);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0667");
 
 name["english"] = "Fedora Core 2 2005-224: sylpheed";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-224 (sylpheed).

This program is an X based fast email client which has features
like:
o user-friendly and intuitive interface
o integrated NetNews client (partially implemented)
o ability of keyboard-only operation
o Mew/Wanderlust-like key bind
o multipart MIME
o unlimited multiple account handling
o message queueing
o assortment function
o XML-based address book

See /usr/share/doc/sylpheed*/README for more information.


* Thu Mar 17 2005 Akira TAGOH - 1.0.3-0.FC2

- New upstream release.
- contains the possible buffer overflow issue.
CVE-2005-0667



Solution : http://www.fedoranews.org/blog/index.php?p=493
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sylpheed package";
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
if ( rpm_check( reference:"sylpheed-debuginfo-1.0.3-0.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sylpheed-1.0.3-0.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"sylpheed-", release:"FC2") )
{
 set_kb_item(name:"CVE-2005-0667", value:TRUE);
}
