#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19634);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0233", "CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0585");
 
 name["english"] = "Fedora Core 3 2005-249: mozilla";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-249 (mozilla).

Mozilla is an open-source web browser, designed for standards
compliance, performance and portability.

Update Information:

Multiple bugs have been found in Mozilla.

Users of Mozilla are advised to upgrade to this updated package which
contains Mozilla version 1.7.6 to correct these issues.


Solution : Get the newest Fedora Updates
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
if ( rpm_check( reference:"mozilla-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-debuginfo-1.7.6-1.3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mozilla-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-1156", value:TRUE);
 set_kb_item(name:"CVE-2004-1380", value:TRUE);
 set_kb_item(name:"CVE-2005-0141", value:TRUE);
 set_kb_item(name:"CVE-2005-0142", value:TRUE);
 set_kb_item(name:"CVE-2005-0143", value:TRUE);
 set_kb_item(name:"CVE-2005-0144", value:TRUE);
 set_kb_item(name:"CVE-2005-0146", value:TRUE);
 set_kb_item(name:"CVE-2005-0147", value:TRUE);
 set_kb_item(name:"CVE-2005-0149", value:TRUE);
 set_kb_item(name:"CVE-2005-0233", value:TRUE);
 set_kb_item(name:"CVE-2005-0399", value:TRUE);
 set_kb_item(name:"CVE-2005-0401", value:TRUE);
 set_kb_item(name:"CVE-2005-0585", value:TRUE);
}
