# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19810);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-11");
 script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-11
(Mozilla Suite, Mozilla Firefox: Multiple vulnerabilities)


    The Mozilla Suite and Firefox are both vulnerable to the following
    issues:
    Tom Ferris reported a heap overflow in IDN-enabled browsers with
    malicious Host: headers (CVE-2005-2871).
    "jackerror" discovered a heap overrun in XBM image processing
    (CVE-2005-2701).
    Mats Palmgren reported a potentially exploitable stack corruption
    using specific Unicode sequences (CVE-2005-2702).
    Georgi Guninski discovered an integer overflow in the JavaScript
    engine (CVE-2005-2705)
    Other issues ranging from DOM object spoofing to request header
    spoofing were also found and fixed in the latest versions
    (CVE-2005-2703, CVE-2005-2704, CVE-2005-2706, CVE-2005-2707).
    The Gecko engine in itself is also affected by some of these issues and
    has been updated as well.
  
Impact

    A remote attacker could setup a malicious site and entice a victim to
    visit it, potentially resulting in arbitrary code execution with the
    victim\'s privileges or facilitated spoofing of known websites.
  
Workaround

    There is no known workaround for all the issues.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2701
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2702
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2703
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2704
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2705
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2706
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2707
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2871
    http://www.mozilla.org/projects/security/known-vulnerabilities.html


Solution: 
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-1.0.7-r2"
    All Mozilla Suite users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-1.7.12-r2"
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-1.0.7"
    All Mozilla Suite binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-bin-1.7.12"
    All Gecko library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/gecko-sdk-1.7.12"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-11] Mozilla Suite, Mozilla Firefox: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Suite, Mozilla Firefox: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.0.7"), vulnerable: make_list("lt 1.0.7")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-libs/gecko-sdk", unaffected: make_list("ge 1.7.12"), vulnerable: make_list("lt 1.7.12")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla", unaffected: make_list("ge 1.7.12-r2"), vulnerable: make_list("lt 1.7.12-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 1.0.7-r2"), vulnerable: make_list("lt 1.0.7-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-bin", unaffected: make_list("ge 1.7.12"), vulnerable: make_list("lt 1.7.12")
)) { security_warning(0); exit(0); }
