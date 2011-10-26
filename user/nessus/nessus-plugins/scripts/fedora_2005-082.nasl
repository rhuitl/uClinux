#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16285);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0162");
 
 name["english"] = "Fedora Core 3 2005-082: openswan";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-082 (openswan).

Openswan is a free implementation of IPSEC & IKE for Linux.

IPsec is Internet Protocol Security and uses strong cryptography to
provide both authentication and encryption services. These services
allow you to build secure tunnels through untrusted networks.
Everything passing through the untrusted net is encrypted by the ipsec
gateway machine and decrypted by the gateway at the other end of the
tunnel. The resulting tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Openswan on a kernel with the 2.6 native IPsec code.

Update Information:
This erratum fixes the remote exploitation of a stack based buffer
overflow vulnerability in Xelerance Corp.'s Openswan, which could
allow attackers to execute arbitrary code.

The vulnerability specifically exists due to a lack of bounds checking
in the pluto application when Openswan is compiled with XAUTH and PAM
support.

The Common Vulnerabilities and Exposures project has assigned
the name CVE-2005-0162 to this problem.



Solution : http://www.fedoranews.org/blog/index.php?p=336
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openswan package";
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
if ( rpm_check( reference:"openswan-2.1.5-2.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openswan-debuginfo-2.1.5-2.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"openswan-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0162", value:TRUE);
}
