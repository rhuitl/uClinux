#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13732);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 2 2004-197: ipsec-tools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-197 (ipsec-tools).

This is the IPsec-Tools package.  You need this package in order to
really use the IPsec functionality in the linux-2.5+ kernels.  This
package builds:

    - libipsec, a PFKeyV2 library
    - setkey, a program to directly manipulate policies and SAs
    - racoon, an IKEv1 keying daemon

Update Information:

When configured to use X.509 certificates to authenticate remote
hosts, ipsec-tools versions 0.3.3 and earlier will attempt to verify
that host certificate, but will not abort the key exchange if the
verification fails.

Users of ipsec-tools should upgrade to this updated package which
contains a backported security patch and is not vulnerable to this
issue.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-197.shtml
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
if ( rpm_check( reference:"ipsec-tools-0.2.5-4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-debuginfo-0.2.5-4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
