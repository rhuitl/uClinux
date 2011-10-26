#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19627);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0398");
 
 name["english"] = "Fedora Core 3 2005-217: ipsec-tools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-217 (ipsec-tools).

This is the IPsec-Tools package.  You need this package in order to
really use the IPsec functionality in the linux-2.5+ kernels.  This
package builds:

- setkey, a program to directly manipulate policies and SAs
- racoon, an IKEv1 keying daemon

Update Information:

This update fixes a potential DoS in parsing ISAKMP headers in racoon.
(CVE-2005-0398)


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ipsec-tools package";
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
if ( rpm_check( reference:"ipsec-tools-0.5-2.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"ipsec-tools-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0398", value:TRUE);
}
