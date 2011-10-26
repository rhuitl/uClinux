# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21348);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-06");
 script_cve_id("CVE-2006-1993");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-06
(Mozilla Firefox: Potential remote code execution)


    Martijn Wargers and Nick Mott discovered a vulnerability when
    rendering malformed JavaScript content. The Mozilla Firefox 1.0 line is
    not affected.
  
Impact

    If JavaScript is enabled, by tricking a user into visiting a
    malicious web page which would send a specially crafted HTML script
    that contains references to deleted objects with the "designMode"
    property enabled, an attacker can crash the web browser and in theory
    manage to execute arbitrary code with the rights of the user running
    the browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1993


Solution: 
    All Mozilla Firefox 1.5 users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-1.5.0.3"
    All Mozilla Firefox 1.5 binary users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/mozilla-firefox-bin-1.5.0.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-06] Mozilla Firefox: Potential remote code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Firefox: Potential remote code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/mozilla-firefox", unaffected: make_list("ge 1.5.0.3", "lt 1.5"), vulnerable: make_list("lt 1.5.0.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.5.0.3", "lt 1.5"), vulnerable: make_list("lt 1.5.0.3")
)) { security_warning(0); exit(0); }
