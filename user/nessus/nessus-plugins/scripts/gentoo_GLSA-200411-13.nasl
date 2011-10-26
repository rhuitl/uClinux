# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15647);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200411-13");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-13
(Portage, Gentoolkit: Temporary file vulnerabilities)


    dispatch-conf and qpkg use predictable filenames for temporary files.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When an
    affected script is called, this would result in the file to be overwritten
    with the rights of the user running the dispatch-conf or qpkg, which could
    be the root user.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All Portage users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/portage-2.0.51-r3"
    All Gentoolkit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-portage/gentoolkit-0.2.0_pre8-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-13] Portage, Gentoolkit: Temporary file vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Portage, Gentoolkit: Temporary file vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-apps/portage", unaffected: make_list("ge 2.0.51-r3"), vulnerable: make_list("le 2.0.51-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-portage/gentoolkit", unaffected: make_list("ge 0.2.0_pre10-r1", "rge 0.2.0_pre8-r1"), vulnerable: make_list("le 0.2.0_pre10")
)) { security_warning(0); exit(0); }
