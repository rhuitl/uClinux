# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19817);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-18
(Qt: Buffer overflow in the included zlib library)


    Qt links to a bundled vulnerable version of zlib when emerged with the
    zlib USE-flag disabled. This may lead to a buffer overflow.
  
Impact

    By creating a specially crafted compressed data stream, attackers can
    overwrite data structures for applications that use Qt, resulting in a
    Denial of Service or potentially arbitrary code execution.
  
Workaround

    Emerge Qt with the zlib USE-flag enabled.
  
References:
    http://www.gentoo.org/security/en/glsa/glsa-200507-05.xml
    http://www.gentoo.org/security/en/glsa/glsa-200507-19.xml
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1849
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2096


Solution: 
    All Qt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/qt-3.3.4-r8"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-18] Qt: Buffer overflow in the included zlib library");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Qt: Buffer overflow in the included zlib library');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-libs/qt", unaffected: make_list("ge 3.3.4-r8"), vulnerable: make_list("lt 3.3.4-r8")
)) { security_warning(0); exit(0); }
