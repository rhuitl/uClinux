#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19261);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0989", "CVE-2005-1159", "CVE-2005-1160", "CVE-2005-1532", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2269", "CVE-2005-2270");
 
 name["english"] = "Fedora Core 3 2005-604: thunderbird";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-604 (thunderbird).

Mozilla Thunderbird is a standalone mail and newsgroup client.


Users of Thunderbird are advised to upgrade to this updated package
that contains Thunderbird version 1.0.6 and is not vulnerable to these
issues.


Solution : http://www.fedoranews.org/blog/index.php?p=778
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the thunderbird package";
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
if ( rpm_check( reference:"thunderbird-1.0.6-1.1.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"thunderbird-debuginfo-1.0.6-1.1.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"thunderbird-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0989", value:TRUE);
 set_kb_item(name:"CVE-2005-1159", value:TRUE);
 set_kb_item(name:"CVE-2005-1160", value:TRUE);
 set_kb_item(name:"CVE-2005-1532", value:TRUE);
 set_kb_item(name:"CVE-2005-2261", value:TRUE);
 set_kb_item(name:"CVE-2005-2265", value:TRUE);
 set_kb_item(name:"CVE-2005-2266", value:TRUE);
 set_kb_item(name:"CVE-2005-2269", value:TRUE);
 set_kb_item(name:"CVE-2005-2270", value:TRUE);
}
