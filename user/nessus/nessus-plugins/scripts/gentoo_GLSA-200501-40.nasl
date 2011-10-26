# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-40.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16431);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200501-40");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-40
(ngIRCd: Buffer overflow)


    Florian Westphal discovered a buffer overflow caused by an integer
    underflow in the Lists_MakeMask() function of lists.c.
  
Impact

    A remote attacker can exploit this buffer overflow to crash the
    ngIRCd daemon and possibly execute arbitrary code with the rights of
    the ngIRCd daemon process.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://arthur.ath.cx/pipermail/ngircd-ml/2005-January/000228.html


Solution: 
    All ngIRCd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-irc/ngIRCd-0.8.2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-40] ngIRCd: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ngIRCd: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-irc/ngircd", unaffected: make_list("ge 0.8.2"), vulnerable: make_list("lt 0.8.2")
)) { security_hole(0); exit(0); }
