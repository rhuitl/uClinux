#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20022);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2969");
 
 name["english"] = "Fedora Core 3 2005-985: openssl096b";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-985 (openssl096b).

The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols.


* Thu Oct  6 2005 Tomas Mraz <tmraz redhat com> 0.9.6b-21.2
- fix CVE-2005-2969 - remove SSL_OP_MSIE_SSLV2_RSA_PADDING which
disables the countermeasure against man in the middle attack in SSLv2
(#169863)
- more fixes for constant time/memory access for DSA signature algorithm
- replaced add-luna patch with new one with right license (#158061)




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl096b package";
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
if ( rpm_check( reference:"openssl096b-0.9.6b-21.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"openssl096b-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2969", value:TRUE);
}
