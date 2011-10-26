# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18090);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-18");
 script_cve_id("CVE-2005-0989");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-18
(Mozilla Firefox, Mozilla Suite: Multiple vulnerabilities)


    The following vulnerabilities were found and fixed in the Mozilla
    Suite and Mozilla Firefox:
    Vladimir V. Perepelitsa
    reported a memory disclosure bug in JavaScript\'s regular expression
    string replacement when using an anonymous function as the replacement
    argument (CVE-2005-0989).
    moz_bug_r_a4 discovered that Chrome
    UI code was overly trusting DOM nodes from the content window, allowing
    privilege escalation via DOM property overrides.
    Michael Krax
    reported a possibility to run JavaScript code with elevated privileges
    through the use of javascript: favicons.
    Michael Krax also
    discovered that malicious Search plugins could run JavaScript in the
    context of the displayed page or stealthily replace existing search
    plugins.
    shutdown discovered a technique to pollute the global
    scope of a window in a way that persists from page to page.
    Doron Rosenberg discovered a possibility to run JavaScript with
    elevated privileges when the user asks to "Show" a blocked popup that
    contains a JavaScript URL.
    Finally, Georgi Guninski reported
    missing Install object instance checks in the native implementations of
    XPInstall-related JavaScript objects.
    The following
    Firefox-specific vulnerabilities have also been discovered:
    Kohei Yoshino discovered a new way to abuse the sidebar panel to
    execute JavaScript with elevated privileges.
    Omar Khan
    reported that the Plugin Finder Service can be tricked to open
    javascript: URLs with elevated privileges.
  
Impact

    The various JavaScript execution with elevated privileges issues
    can be exploited by a remote attacker to install malicious code or
    steal data. The memory disclosure issue can be used to reveal
    potentially sensitive information. Finally, the cache pollution issue
    and search plugin abuse can be leveraged in cross-site-scripting
    attacks.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.mozilla.org/projects/security/known-vulnerabilities.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0989


Solution: 
    All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-1.0.3"
    All Mozilla Firefox binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-1.0.3"
    All Mozilla Suite users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-1.7.7"
    All Mozilla Suite binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-bin-1.7.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-18] Mozilla Firefox, Mozilla Suite: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Firefox, Mozilla Suite: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 1.0.3"), vulnerable: make_list("lt 1.0.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla", unaffected: make_list("ge 1.7.7"), vulnerable: make_list("lt 1.7.7")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.0.3"), vulnerable: make_list("lt 1.0.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-bin", unaffected: make_list("ge 1.7.7"), vulnerable: make_list("lt 1.7.7")
)) { security_warning(0); exit(0); }
