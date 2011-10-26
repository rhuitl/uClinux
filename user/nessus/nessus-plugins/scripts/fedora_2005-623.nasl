#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19291);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1852");
 
 name["english"] = "Fedora Core 3 2005-623: kdenetwork";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-623 (kdenetwork).

Networking applications for the K Desktop Environment.

Update Information:

Multiple integer overflow flaws were found in the way Kopete processes
Gadu-Gadu messages. A remote attacker could send a specially crafted
Gadu-Gadu message which would cause Kopete to crash or possibly
execute
arbitrary code. The Common Vulnerabilities and Exposures project
assigned the name CVE-2005-1852 to this issue.

Users of Kopete should update to these packages which contain a
patch to correct this issue.


Solution : http://www.fedoranews.org/blog/index.php?p=785
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdenetwork package";
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
if ( rpm_check( reference:"kdenetwork-3.3.1-3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-devel-3.3.1-3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-nowlistening-3.3.1-3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-debuginfo-3.3.1-3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdenetwork-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-1852", value:TRUE);
}
