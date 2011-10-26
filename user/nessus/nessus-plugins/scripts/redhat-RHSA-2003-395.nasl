#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12439);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0971");

 name["english"] = "RHSA-2003-395: gnupg";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gnupg packages are now available for Red Hat Enterprise Linux.
  These updates disable the ability to generate ElGamal keys (used for both
  signing and encrypting) and disable the ability to use ElGamal public keys
  for encrypting data.

  GnuPG is a utility for encrypting data and creating digital signatures.

  Phong Nguyen identified a severe bug in the way GnuPG creates and uses
  ElGamal keys, when those keys are used both to sign and encrypt data. This
  vulnerability can be used to trivially recover the private key. While the
  default behavior of GnuPG when generating keys does not lead to the
  creation of unsafe keys, by overriding the default settings an unsafe key
  could have been created.

  If you are using ElGamal keys, you should revoke those keys immediately.

  The packages included in this update do not make ElGamal keys safe to use;
  they merely include a patch by David Shaw that disables functions that
  would generate or use ElGamal keys.

  To determine if your key is affected, run the following command to obtain a
  list of secret keys that you have on your secret keyring:

  gpg --list-secret-keys

  The output of this command includes both the size and type of the keys
  found, and will look similar to this example:

  /home/example/.gnupg/secring.gpg
  ----------------------------------------------------
  sec 1024D/01234567 2000-10-17 Example User <example@example.com>
  uid Example User <example@example.com>

  The key length, type, and ID are listed together, separated by a forward
  slash. In the example output above, the key\'s type is "D" (DSA, sign
  and encrypt). Your key is unsafe if and only if the key type is "G"
  (ElGamal, sign and encrypt). In the above example, the secret key is safe
  to use, while the secret key in the following example is not:

  /home/example/.gnupg/secring.gpg
  ----------------------------------------------------
  sec 1024G/01234567 2000-10-17 Example User <example@example.com>
  uid Example User <example@example.com>

  For more details regarding this issue, as well as instructions on how to
  revoke any keys that are unsafe, refer to the advisory available from the
  GnuPG web site:

  http://www.gnupg.org/




Solution : http://rhn.redhat.com/errata/RHSA-2003-395.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnupg packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gnupg-1.0.7-13", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.1-10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gnupg-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0971", value:TRUE);
}
if ( rpm_exists(rpm:"gnupg-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0971", value:TRUE);
}

set_kb_item(name:"RHSA-2003-395", value:TRUE);
