# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-29.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19360);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200507-29");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-29
(pstotext: Remote execution of arbitrary code)


    Max Vozeler reported that pstotext calls the GhostScript
    interpreter on untrusted PostScript files without specifying the
    -dSAFER option.
  
Impact

    An attacker could craft a malicious PostScript file and entice a
    user to run pstotext on it, resulting in the execution of arbitrary
    commands with the permissions of the user running pstotext.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://secunia.com/advisories/16183/


Solution: 
    All pstotext users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/pstotext-1.8g-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-29] pstotext: Remote execution of arbitrary code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'pstotext: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/pstotext", unaffected: make_list("ge 1.8g-r1"), vulnerable: make_list("lt 1.8g-r1")
)) { security_warning(0); exit(0); }
