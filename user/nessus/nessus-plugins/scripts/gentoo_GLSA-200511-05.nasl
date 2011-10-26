# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20155);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-05");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-05
(GNUMP3d: Directory traversal and XSS vulnerabilities)


    Steve Kemp reported about two cross-site scripting attacks that
    are related to the handling of files (CVE-2005-3424, CVE-2005-3425).
    Also reported is a directory traversal vulnerability which comes from
    the attempt to sanitize input paths (CVE-2005-3123).
  
Impact

    A remote attacker could exploit this to disclose sensitive
    information or inject and execute malicious script code, potentially
    compromising the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3123
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3424
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3425


Solution: 
    All GNUMP3d users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/gnump3d-2.9.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-05] GNUMP3d: Directory traversal and XSS vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNUMP3d: Directory traversal and XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/gnump3d", unaffected: make_list("ge 2.9.7"), vulnerable: make_list("lt 2.9.7")
)) { security_warning(0); exit(0); }
