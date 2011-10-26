# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-27.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16075);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200412-27");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-27
(PHProjekt: Remote code execution vulnerability)


    cYon discovered that the authform.inc.php script allows a remote
    user to define the global variable $path_pre.
  
Impact

    A remote attacker can exploit this vulnerability to force
    authform.inc.php to download and execute arbitrary PHP code with the
    privileges of the web server user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.phprojekt.com/modules.php?op=modload&name=News&file=article&sid=193&mode=thread&order=0


Solution: 
    All PHProjekt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phprojekt-4.2-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-27] PHProjekt: Remote code execution vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHProjekt: Remote code execution vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phprojekt", unaffected: make_list("ge 4.2-r2"), vulnerable: make_list("lt 4.2-r2")
)) { security_hole(0); exit(0); }
