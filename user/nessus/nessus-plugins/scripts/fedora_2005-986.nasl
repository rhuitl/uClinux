#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20023);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2969");
 
 name["english"] = "Fedora Core 4 2005-986: openssl097a";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-986 (openssl097a).

The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols.


* Tue Oct 11 2005 Tomas Mraz <tmraz redhat com> 0.9.7a-3.1
- fix CVE-2005-2969 - remove SSL_OP_MSIE_SSLV2_RSA_PADDING which
disables the countermeasure against man in the middle attack in SSLv2
(#169863)
- more fixes for constant time/memory access for DSA signature algorithm
- updated ICA engine patch




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl097a package";
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
if ( rpm_check( reference:"openssl097a-0.9.7a-3.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"openssl097a-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2969", value:TRUE);
}
