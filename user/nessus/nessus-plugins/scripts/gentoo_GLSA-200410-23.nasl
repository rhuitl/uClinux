# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15559);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200410-23");
 script_cve_id("CVE-2004-0891");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-23
(Gaim: Multiple vulnerabilities)


    A possible buffer overflow exists in the code processing MSN SLP messages
    (CVE-2004-0891). memcpy() was used without validating the size of the
    buffer, and an incorrect buffer was used as destination under certain
    circumstances. Additionally, memory allocation problems were found in the
    processing of MSN SLP messages and the receiving of files. These issues
    could lead Gaim to try to allocate more memory than available, resulting in
    the crash of the application.
  
Impact

    A remote attacker could crash Gaim and possibly execute arbitrary code by
    exploiting the buffer overflow.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0891
    http://gaim.sourceforge.net/security/


Solution: 
    All Gaim users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-im/gaim-1.0.2"
    # emerge ">=net-im/gaim-1.0.2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-23] Gaim: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 1.0.2"), vulnerable: make_list("lt 1.0.2")
)) { security_hole(0); exit(0); }
