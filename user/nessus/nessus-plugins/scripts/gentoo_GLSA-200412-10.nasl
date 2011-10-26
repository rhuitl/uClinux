# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15971);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200412-10");
 script_cve_id("CVE-2004-1138");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-10
(Vim, gVim: Vulnerable options in modelines)


    Gentoo\'s Vim maintainer, Ciaran McCreesh, found several
    vulnerabilities related to the use of options in Vim modelines. Options
    like \'termcap\', \'printdevice\', \'titleold\', \'filetype\', \'syntax\',
    \'backupext\', \'keymap\', \'patchmode\' or \'langmenu\' could be abused.
  
Impact

    A local attacker could write a malicious file in a world readable
    location which, when opened in a modeline-enabled Vim, could trigger
    arbitrary commands with the rights of the user opening the file,
    resulting in privilege escalation. Please note that modelines are
    disabled by default in the /etc/vimrc file provided in Gentoo.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1138


Solution: 
    All Vim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/vim-6.3-r2"
    All gVim users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/gvim-6.3-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-10] Vim, gVim: Vulnerable options in modelines");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Vim, gVim: Vulnerable options in modelines');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-editors/vim", unaffected: make_list("ge 6.3-r2"), vulnerable: make_list("lt 6.3-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-editors/gvim", unaffected: make_list("ge 6.3-r2"), vulnerable: make_list("lt 6.3-r2")
)) { security_warning(0); exit(0); }
