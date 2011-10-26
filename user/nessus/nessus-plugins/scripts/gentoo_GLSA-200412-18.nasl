# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16005);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200412-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-18
(abcm2ps: Buffer overflow vulnerability)


    Limin Wang has located a buffer overflow inside the put_words()
    function in the abcm2ps code.
  
Impact

    A remote attacker could convince the victim to download a
    specially-crafted ABC file. Upon execution, this file would trigger the
    buffer overflow and lead to the execution of arbitrary code with the
    permissions of the user running abcm2ps.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://moinejf.free.fr/abcm2ps-3.txt
    http://secunia.com/advisories/13523/


Solution: 
    All abcm2ps users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/abcm2ps-3.7.21"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-18] abcm2ps: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'abcm2ps: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/abcm2ps", unaffected: make_list("ge 3.7.21"), vulnerable: make_list("lt 3.7.21")
)) { security_warning(0); exit(0); }
