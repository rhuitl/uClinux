#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20242);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 3 2005-1092: openswan";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1092 (openswan).


Openswan is a free implementation of IPSEC & IKE for Linux.  IPSEC is
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Openswan on a freeswan enabled kernel.

Update Information:

NISCC has reported two Denial of Service issues in Openswan.
The first involves a specially crafted 3DES packet with an
invalid key length.

The Openswan project has relased version 2.4.4 to fix both
issues.

See [8]http://www.openswan.org/ for details.


Solution : Get the newest Fedora Updates
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
if ( rpm_check( reference:"openswan-2.4.4-0.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openswan-doc-2.4.4-0.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
