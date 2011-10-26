# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15527);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200410-18");
 script_cve_id("CVE-2004-0967");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-18
(Ghostscript: Insecure temporary file use in multiple scripts)


    The pj-gs.sh, ps2epsi, pv.sh and sysvlp.sh scripts create temporary files
    in world-writeable directories with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When an
    affected script is called, this would result in the file to be overwritten
    with the rights of the user running the script, which could be the root
    user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0967


Solution: 
    Ghostscript users on all architectures except PPC should upgrade to the
    latest version:
    # emerge sync
    # emerge -pv ">=app-text/ghostscript-7.07.1-r7"
    # emerge ">=app-text/ghostscript-7.07.1-r7"
    Ghostscript users on the PPC architecture should upgrade to the latest
    stable version on their architecture:
    # emerge sync
    # emerge -pv ">=app-text/ghostscript-7.05.6-r2"
    # emerge ">=app-text/ghostscript-7.05.6-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-18] Ghostscript: Insecure temporary file use in multiple scripts");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ghostscript: Insecure temporary file use in multiple scripts');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/ghostscript", unaffected: make_list("ge 7.07.1-r7", "rge 7.05.6-r2"), vulnerable: make_list("lt 7.07.1-r7")
)) { security_warning(0); exit(0); }
