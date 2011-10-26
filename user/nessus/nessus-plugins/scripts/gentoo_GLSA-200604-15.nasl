# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21297);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200604-15");
 script_cve_id("CVE-2006-1905");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200604-15
(xine-ui: Format string vulnerabilities)


    Ludwig Nussel discovered that xine-ui incorrectly implements
    formatted printing.
  
Impact

    By constructing a malicious playlist file, a remote attacker could
    exploit these vulnerabilities to execute arbitrary code with the rights
    of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1905


Solution: 
    All xine-ui users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/xine-ui-0.99.4-r5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200604-15] xine-ui: Format string vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-ui: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/xine-ui", unaffected: make_list("ge 0.99.4-r5"), vulnerable: make_list("lt 0.99.4-r5")
)) { security_warning(0); exit(0); }
