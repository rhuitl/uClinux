# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21126);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-19");
 script_cve_id("CVE-2006-1061");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-19
(cURL/libcurl: Buffer overflow in the handling of TFTP URLs)


    Ulf Harnhammar reported a possible buffer overflow in the handling
    of TFTP URLs in libcurl due to the lack of boundary checks.
  
Impact

    An attacker could exploit this vulnerability to compromise a
    user\'s system by enticing the user to request a malicious URL with
    cURL/libcurl or to use a HTTP server redirecting to a malicious TFTP
    URL.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://curl.haxx.se/docs/adv_20060320.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1061


Solution: 
    All cURL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/curl-7.15.1-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-19] cURL/libcurl: Buffer overflow in the handling of TFTP URLs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cURL/libcurl: Buffer overflow in the handling of TFTP URLs');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/curl", unaffected: make_list("rge 7.15.1-r1", "ge 7.15.3", "le 7.14.1"), vulnerable: make_list("lt 7.15.3")
)) { security_warning(0); exit(0); }
