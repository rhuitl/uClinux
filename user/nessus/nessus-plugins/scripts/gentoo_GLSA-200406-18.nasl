# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14529);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-18
(gzip: Insecure creation of temporary files)


    The script gzexe included with gzip contains a bug in the code that handles
    tempfile creation. If the creation of a temp file fails when using gzexe
    fails instead of bailing out it executes the command given as argument.
  
Impact

    This could lead to priviege escalation by running commands under the rights
    of the user running the self extracting file.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  

Solution: 
    All gzip users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-arch/gzip-1.3.3-r4"
    # emerge ">=app-arch/gzip-1.3.3-r4"
    Additionally, once the upgrade is complete, all self extracting files
    created with earlier versions gzexe should be recreated, since the
    vulnerability is actually embedded in those executables.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-18] gzip: Insecure creation of temporary files");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gzip: Insecure creation of temporary files');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/gzip", unaffected: make_list("ge 1.3.3-r4"), vulnerable: make_list("le 1.3.3-r3")
)) { security_warning(0); exit(0); }
