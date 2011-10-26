# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20033);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200510-13");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-13
(SPE: Insecure file permissions)


    It was reported that due to an oversight all SPE\'s files are set
    as world-writeable.
  
Impact

    A local attacker could modify the executable files, causing
    arbitrary code to be executed with the permissions of the user running
    SPE.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All SPE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-util/spe
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-13] SPE: Insecure file permissions");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SPE: Insecure file permissions');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-util/spe", unaffected: make_list("ge 0.7.5c-r1", "rge 0.5.1f-r1"), vulnerable: make_list("lt 0.7.5c-r1")
)) { security_warning(0); exit(0); }
