#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19276);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2263", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
 
 name["english"] = "Fedora Core 4 2005-619: mozilla";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-619 (mozilla).

Mozilla is an open-source Web browser, designed for standards
compliance, performance, and portability.


Users of Mozilla are advised to upgrade to these updated packages, which
contain Mozilla version 1.7.10 and are not vulnerable to these issues.


Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_mozilla-1.7.10-1.5.1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mozilla package";
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
if ( rpm_check( reference:"mozilla-1.7.10-1.5.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.10-1.5.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.10-1.5.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.10-1.5.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.10-1.5.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.10-1.5.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.10-1.5.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.10-1.5.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mozilla-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-1937", value:TRUE);
 set_kb_item(name:"CVE-2005-2260", value:TRUE);
 set_kb_item(name:"CVE-2005-2261", value:TRUE);
 set_kb_item(name:"CVE-2005-2263", value:TRUE);
 set_kb_item(name:"CVE-2005-2265", value:TRUE);
 set_kb_item(name:"CVE-2005-2266", value:TRUE);
 set_kb_item(name:"CVE-2005-2267", value:TRUE);
 set_kb_item(name:"CVE-2005-2268", value:TRUE);
 set_kb_item(name:"CVE-2005-2269", value:TRUE);
 set_kb_item(name:"CVE-2005-2270", value:TRUE);
}
