# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17128);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-23");
 script_cve_id("CVE-2005-0011");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-23
(KStars: Buffer overflow in fliccd)


    Erik Sjolund discovered a buffer overflow in fliccd which is part
    of the INDI support in KStars.
  
Impact

    An attacker could exploit this vulnerability to execute code with
    elevated privileges. If fliccd does not run as daemon remote
    exploitation of this vulnerability is not possible. KDE as shipped by
    Gentoo does not start the daemon in the default installation.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0011


Solution: 
    All KStars users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdeedu-3.3.2-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-23] KStars: Buffer overflow in fliccd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KStars: Buffer overflow in fliccd');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdeedu", unaffected: make_list("ge 3.3.2-r1"), vulnerable: make_list("lt 3.3.2-r1")
)) { security_hole(0); exit(0); }
