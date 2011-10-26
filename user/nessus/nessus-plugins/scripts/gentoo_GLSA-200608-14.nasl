# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22200);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-14");
 script_cve_id("CVE-2006-3668");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-14
(DUMB: Heap buffer overflow)


    Luigi Auriemma found a heap-based buffer overflow in the
    it_read_envelope function which reads the envelope values for volume,
    pan and pitch of the instruments referenced in a ".it" (Impulse
    Tracker) file with a large number of nodes.
  
Impact

    By enticing a user to load a malicious ".it" (Impulse Tracker) file, an
    attacker may execute arbitrary code with the rights of the user running
    the application that uses a vulnerable DUMB library.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3668


Solution: 
    All users of DUMB should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/dumb-0.9.3-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-14] DUMB: Heap buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'DUMB: Heap buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/dumb", unaffected: make_list("ge 0.9.3-r1"), vulnerable: make_list("lt 0.9.3-r1")
)) { security_warning(0); exit(0); }
