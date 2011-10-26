#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13663);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "Fedora Core 1 2003-025: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2003-025 (gnupg).

GnuPG (GNU Privacy Guard) is a GNU utility for encrypting data and
creating digital signatures. GnuPG has advanced key management
capabilities and is compliant with the proposed OpenPGP Internet
standard described in RFC2440. Since GnuPG doesn't use any patented
algorithm, it is not compatible with any version of PGP2 (PGP2.x uses
only IDEA for symmetric-key encryption, which is patented worldwide).

Update Information:

Phong Nguyen identified a severe bug in the way GnuPG creates and
uses ElGamal keys, when those keys are used both to sign and encrypt
data.  This vulnerability can be used to trivially recover the
private key.  While the default behavior of GnuPG when generating
keys does not lead to the creation of unsafe keys, by overriding the
default settings an unsafe key could have been created.

If you are using ElGamal keys, you should revoke those keys
immediately.

The packages included in this update do not make ElGamal keys safe to
use; they merely include a patch by David Shaw that disables
functions that would generate or use ElGamal keys for encryption.



Solution : http://www.fedoranews.org/updates/FEDORA-2003-025.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnupg package";
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
if ( rpm_check( reference:"gnupg-1.2.3-2", prefix:"gnupg-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
