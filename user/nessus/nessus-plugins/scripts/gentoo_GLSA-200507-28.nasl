# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-28.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19330);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-28");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-28
(AMD64 x86 emulation base libraries: Buffer overflow)


    Earlier versions of emul-linux-x86-baselibs contain a vulnerable
    version of zlib, which may lead to a buffer overflow.
  
Impact

    By creating a specially crafted compressed data stream, attackers
    can overwrite data structures for applications that use the x86
    emulation base libraries for AMD64, resulting in a Denial of Service
    and potentially arbitrary code execution.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.gentoo.org/security/en/glsa/glsa-200507-05.xml
    http://www.gentoo.org/security/en/glsa/glsa-200507-19.xml
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1849
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2096


Solution: 
    All AMD64 x86 emulation base libraries users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-baselibs-2.2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-28] AMD64 x86 emulation base libraries: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AMD64 x86 emulation base libraries: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-emulation/emul-linux-x86-baselibs", arch: "AMD64", unaffected: make_list("ge 2.2"), vulnerable: make_list("lt 2.2")
)) { security_hole(0); exit(0); }
