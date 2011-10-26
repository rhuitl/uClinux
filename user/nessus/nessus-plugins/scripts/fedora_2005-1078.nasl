#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20193);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2929");
 
 name["english"] = "Fedora Core 3 2005-1078: lynx";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1078 (lynx).

Lynx is a text-based Web browser. Lynx does not display any images,
but it does support frames, tables, and most other HTML tags. One
advantage Lynx has over graphical browsers is speed; Lynx starts and
exits quickly and swiftly displays webpages.

Update Information:

This update fixes CVE-2005-2929 (lynxcgi: URLs).


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lynx package";
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
if ( rpm_check( reference:"lynx-2.8.5-18.0.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"lynx-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2929", value:TRUE);
}
