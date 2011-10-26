# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14460);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200403-09");
 script_cve_id("CVE-2003-1023");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-09
(Buffer overflow in Midnight Commander)


    A stack-based buffer overflow has been found in Midnight Commander\'s
    virtual filesystem.
  
Impact

    This overflow allows an attacker to run arbitrary code on the user\'s
    computer during the symlink conversion process.
  
Workaround

    While a workaround is not currently known for this issue, all users are
    advised to upgrade to the latest version of the affected package.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1023


Solution: 
    All users should upgrade to the current version of the affected package:
    # emerge sync
    # emerge -pv ">=app-misc/mc-4.6.0-r5"
    # emerge ">=app-misc/mc-4.6.0-r5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-09] Buffer overflow in Midnight Commander");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Buffer overflow in Midnight Commander');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-misc/mc", unaffected: make_list("ge 4.6.0-r5"), vulnerable: make_list("le 4.6.0-r4")
)) { security_hole(0); exit(0); }
