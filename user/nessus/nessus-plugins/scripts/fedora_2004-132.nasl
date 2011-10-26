#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13707);
 script_bugtraq_id(10172);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0403");
 
 name["english"] = "Fedora Core 2 2004-132: ipsec-tools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-132 (ipsec-tools).

This is the IPsec-Tools package.  You need this package in order to
really use the IPsec functionality in the linux-2.5+ kernels.  This
package builds:

        - libipsec, a PFKeyV2 library
	- setkey, a program to directly manipulate policies and SAs
	- racoon, an IKEv1 keying daemon

Update Information:

An updated ipsec-tools package that fixes vulnerabilities in racoon (the
ISAKMP daemon) is now available.

When ipsec-tools receives an ISAKMP header, it will attempt to allocate
sufficient memory for the entire ISAKMP message according to the header's
length field. If an attacker crafts an ISAKMP header with a extremely large
value in the length field, racoon may exceed operating system resource
limits and be terminated, resulting in a denial of service. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-0403 to this issue.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-132.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ipsec-tools package";
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
if ( rpm_check( reference:"ipsec-tools-0.2.5-2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-debuginfo-0.2.5-2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"ipsec-tools-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0403", value:TRUE);
}
