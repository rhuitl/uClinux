#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13674);
 script_bugtraq_id(9641);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0078");
 
 name["english"] = "Fedora Core 1 2004-061: mutt";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-061 (mutt).

Mutt is a text-mode mail user agent. Mutt supports color, threading,
arbitrary key remapping, and a lot of customization.

You should install mutt if you have used it in the past and you prefer
it, or if you are new to mail programs and have not decided which one
you are going to use.

Update Information:

This package fixes CVE-2004-0078, where a specifc message could cause
mutt to crash. This is the vulnerability fixed in the recently released
mutt-1.4.2.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-061.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mutt package";
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
if ( rpm_check( reference:"mutt-1.4.1-5", prefix:"mutt-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mutt-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0078", value:TRUE);
}
