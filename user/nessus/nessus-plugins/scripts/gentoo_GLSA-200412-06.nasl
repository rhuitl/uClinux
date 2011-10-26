# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15933);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200412-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-06
(PHProjekt: setup.php vulnerability)


    Martin Muench, from it.sec, found a flaw in the setup.php file.
  
Impact

    Successful exploitation of the flaw allows a remote attacker
    without admin rights to make unauthorized changes to PHProjekt
    configuration.
  
Workaround

    As a workaround, you could replace the existing setup.php file in
    PHProjekt root directory by the one provided on the PHProjekt Advisory
    (see References).
  
References:
    http://www.phprojekt.com/modules.php?op=modload&name=News&file=article&sid=189&mode=thread&order=0


Solution: 
    All PHProjekt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phprojekt-4.2-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-06] PHProjekt: setup.php vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHProjekt: setup.php vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phprojekt", unaffected: make_list("ge 4.2-r1"), vulnerable: make_list("lt 4.2-r1")
)) { security_warning(0); exit(0); }
