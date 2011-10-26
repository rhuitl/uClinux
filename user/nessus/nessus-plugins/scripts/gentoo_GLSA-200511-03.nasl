# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20153);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-03");
 script_cve_id("CVE-2005-2974", "CVE-2005-3350");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-03
(giflib: Multiple vulnerabilities)


    Chris Evans and Daniel Eisenbud independently discovered two
    out-of-bounds memory write operations and a NULL pointer dereference in
    giflib.
  
Impact

    An attacker could craft a malicious GIF image and entice users to
    load it using an application making use of the giflib library,
    resulting in an application crash or potentially the execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2974
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3350


Solution: 
    All giflib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/giflib-4.1.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-03] giflib: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'giflib: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/giflib", unaffected: make_list("ge 4.1.4"), vulnerable: make_list("lt 4.1.4")
)) { security_warning(0); exit(0); }
