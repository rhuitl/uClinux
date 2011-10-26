# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20142);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-02
(QDBM, ImageMagick, GDAL: RUNPATH issues)


    Some packages may introduce insecure paths into the list of
    directories that are searched for libraries at runtime. Furthermore,
    packages depending on the MakeMaker Perl module for build configuration
    may have incorrectly copied the LD_RUN_PATH into the DT_RPATH.
  
Impact

    A local attacker, who is a member of the "portage" group, could
    create a malicious shared object in the Portage temporary build
    directory that would be loaded at runtime by a dependent executable,
    potentially resulting in privilege escalation.
  
Workaround

    Only grant "portage" group rights to trusted users.
  

Solution: 
    All QDBM users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/qdbm-1.8.33-r2"
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.2.4.2-r1"
    All GDAL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose sci-libs/gdal
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-02] QDBM, ImageMagick, GDAL: RUNPATH issues");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'QDBM, ImageMagick, GDAL: RUNPATH issues');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/qdbm", unaffected: make_list("ge 1.8.33-r2"), vulnerable: make_list("lt 1.8.33-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "sci-libs/gdal", unaffected: make_list("ge 1.3.0-r1", "rge 1.2.6-r4"), vulnerable: make_list("lt 1.3.0-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.2.4.2-r1"), vulnerable: make_list("lt 6.2.4.2-r1")
)) { security_warning(0); exit(0); }
