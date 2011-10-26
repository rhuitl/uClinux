# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20329);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-09");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-09
(cURL: Off-by-one errors in URL handling)


    Stefan Esser from the Hardened-PHP Project has reported a
    vulnerability in cURL that allows for a local buffer overflow when cURL
    attempts to parse specially crafted URLs. The URL can be specially
    crafted in one of two ways: the URL could be malformed in a way that
    prevents a terminating null byte from being added to either a hostname
    or path buffer; or the URL could contain a "?" separator in the
    hostname portion, which causes a "/" to be prepended to the resulting
    string.
  
Impact

    An attacker capable of getting cURL to parse a maliciously crafted
    URL could cause a denial of service or execute arbitrary code with the
    privileges of the user making the call to cURL. An attacker could also
    escape open_basedir or safe_mode pseudo-restrictions when exploiting
    this problem from within a PHP program when PHP is compiled with
    libcurl.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4077
    http://www.hardened-php.net/advisory_242005.109.html


Solution: 
    All cURL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/curl-7.15.1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-09] cURL: Off-by-one errors in URL handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cURL: Off-by-one errors in URL handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/curl", unaffected: make_list("ge 7.15.1"), vulnerable: make_list("lt 7.15.1")
)) { security_warning(0); exit(0); }
