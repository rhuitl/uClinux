#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19737);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2876");
 
 name["english"] = "Fedora Core 3 2005-886: util-linux";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-886 (util-linux).

The util-linux package contains a large variety of low-level system
utilities that are necessary for a Linux system to function. Among
others, Util-linux contains the fdisk configuration tool and the login
program.


* Wed Sep 14 2005 Karel Zak <kzak redhat com> 2.12a-24.5
- fix #168207 - CVE-2005-2876 umount unsafe -r usage




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the util-linux package";
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
if ( rpm_check( reference:"util-linux-2.12a-24.5", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"util-linux-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2876", value:TRUE);
}
