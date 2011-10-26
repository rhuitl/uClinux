# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15445);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-07");
 script_cve_id("CVE-2000-1137");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-07
(ed: Insecure temporary file handling)


    ed insecurely creates temporary files in world-writeable directories with
    predictable names. Given that ed is used in various system shell scripts,
    they are by extension affected by the same vulnerability.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When ed is
    called, this would result in file access with the rights of the user
    running the utility, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1137


Solution: 
    All ed users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=sys-apps/ed-0.2-r4"
    # emerge ">=sys-apps/ed-0.2-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-07] ed: Insecure temporary file handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ed: Insecure temporary file handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-apps/ed", unaffected: make_list("ge 0.2-r4"), vulnerable: make_list("le 0.2-r3")
)) { security_warning(0); exit(0); }
