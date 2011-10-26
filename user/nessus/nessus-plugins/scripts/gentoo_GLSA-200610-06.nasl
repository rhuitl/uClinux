# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22892);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200610-06");
 script_cve_id("CVE-2006-4339", "CVE-2006-4340");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200610-06
(Mozilla Network Security Service (NSS): RSA signature forgery)


    Daniel Bleichenbacher discovered that it might be possible to forge
    signatures signed by RSA keys with the exponent of 3. This affects a
    number of RSA signature implementations, including Mozilla\'s NSS.
  
Impact

    Since several Certificate Authorities (CAs) are using an exponent of 3
    it might be possible for an attacker to create a key with a false CA
    signature. This impacts any software using the NSS library, like the
    Mozilla products Firefox, Thunderbird and Seamonkey.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4339
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4340


Solution: 
    All NSS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/nss-3.11.3"
    Note: As usual after updating a library, you should run
    \'revdep-rebuild\' (from the app-portage/gentoolkit package) to ensure
    that all applications linked to it are properly rebuilt.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200610-06] Mozilla Network Security Service (NSS): RSA signature forgery");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Network Security Service (NSS): RSA signature forgery');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-libs/nss", unaffected: make_list("ge 3.11.3"), vulnerable: make_list("lt 3.11.3")
)) { security_warning(0); exit(0); }
