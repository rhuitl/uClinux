# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-31.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17620);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-31");
 script_cve_id("CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0402");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-31
(Mozilla Firefox: Multiple vulnerabilities)


    The following vulnerabilities were found and fixed in Mozilla
    Firefox:
    Mark Dowd from ISS X-Force reported an
    exploitable heap overrun in the GIF processing of obsolete Netscape
    extension 2 (CVE-2005-0399)
    Kohei Yoshino discovered that a
    page bookmarked as a sidebar could bypass privileges control
    (CVE-2005-0402)
    Michael Krax reported a new way to bypass XUL
    security restrictions through drag-and-drop of items like scrollbars
    (CVE-2005-0401)
  
Impact

    The GIF heap overflow could be triggered by a malicious GIF
    image that would end up executing arbitrary code with the rights of the
    user running Firefox
    By tricking the user into bookmarking a
    malicious page as a Sidebar, a remote attacker could potentially
    execute arbitrary code with the rights of the user running the
    browser
    By setting up a malicious website and convincing users
    to obey very specific drag-and-drop instructions, attackers may
    leverage drag-and-drop features to bypass XUL security restrictions,
    which could be used as a stepping stone to exploit other
    vulnerabilities
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0399
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0401
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0402
    http://www.mozilla.org/projects/security/known-vulnerabilities.html


Solution: 
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-1.0.2"
    All Mozilla Firefox binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-1.0.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-31] Mozilla Firefox: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Firefox: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 1.0.2"), vulnerable: make_list("lt 1.0.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.0.2"), vulnerable: make_list("lt 1.0.2")
)) { security_warning(0); exit(0); }
