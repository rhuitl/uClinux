#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20141);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2004-0079");

 name["english"] = "RHSA-2005-830: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenSSL096b compatibility packages that fix a remote denial of
  service vulnerability are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The OpenSSL toolkit implements Secure Sockets Layer (SSL v2/v3),
  Transport Layer Security (TLS v1) protocols, and serves as a full-strength
  general purpose cryptography library. OpenSSL 0.9.6b libraries are provided
  for Red Hat Enterprise Linux 3 and 4 to allow compatibility with legacy
  applications.

  Testing performed by the OpenSSL group using the Codenomicon TLS Test Tool
  uncovered a null-pointer assignment in the do_change_cipher_spec()
  function. A remote attacker could perform a carefully crafted SSL/TLS
  handshake against a server that uses the OpenSSL library in such a way as
  to cause OpenSSL to crash. Depending on the server this could lead to a
  denial of service. (CVE-2004-0079)

  This issue was reported as not affecting OpenSSL versions prior to 0.9.6c,
  and testing with the Codenomicon Test Tool showed that OpenSSL 0.9.6b as
  shipped as a compatibility library with Red Hat Enterprise Linux 3 and 4
  did not crash. However, an alternative reproducer has been written which
  shows that this issue does affect versions of OpenSSL prior to 0.9.6c.

  Note that Red Hat does not ship any applications with Red Hat Enterprise
  Linux 3 or 4 that use these compatibility libraries.

  Users of the OpenSSL096b compatibility package are advised to upgrade to
  these updated packages, which contain a patch provided by the OpenSSL group
  that protect against this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-830.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssl096b-0.9.6b-16.42", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-22.42", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openssl-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0079", value:TRUE);
}
if ( rpm_exists(rpm:"openssl-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-0079", value:TRUE);
}

set_kb_item(name:"RHSA-2005-830", value:TRUE);
