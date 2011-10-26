# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21705);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-12");
 script_cve_id("CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2777", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-12
(Mozilla Firefox: Multiple vulnerabilities)


    A number of vulnerabilities were found and fixed in Mozilla
    Firefox. For details please consult the references below.
  
Impact

    By enticing the user to visit a malicious website, a remote
    attacker can inject arbitrary HTML and JavaScript Code into the user\'s
    browser, execute JavaScript code with elevated privileges and possibly
    execute arbitrary code with the permissions of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2775
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2776
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2777
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2778
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2779
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2780
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2782
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2783
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2784
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2785
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2786
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2787
    http://www.mozilla.org/projects/security/known-vulnerabilities.html#Firefox


Solution: 
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-1.5.0.4"
    All Mozilla Firefox binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-1.5.0.4"
    Note: There is no stable fixed version for the Alpha
    architecture yet. Users of Mozilla Firefox on Alpha should consider
    unmerging it until such a version is available.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-12] Mozilla Firefox: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Firefox: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.5.0.4"), vulnerable: make_list("lt 1.5.0.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 1.5.0.4"), vulnerable: make_list("lt 1.5.0.4")
)) { security_warning(0); exit(0); }
