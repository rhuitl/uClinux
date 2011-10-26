# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19974);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200510-04");
 script_cve_id("CVE-2005-3011");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-04
(Texinfo: Insecure temporary file creation)


    Frank Lichtenheld has discovered that the "sort_offline()"
    function in texindex insecurely creates temporary files with
    predictable filenames.
  
Impact

    A local attacker could create symbolic links in the temporary
    files directory, pointing to a valid file somewhere on the filesystem.
    When texindex is executed, this would result in the file being
    overwritten with the rights of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3011


Solution: 
    All Texinfo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/texinfo-4.8-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-04] Texinfo: Insecure temporary file creation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Texinfo: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-apps/texinfo", unaffected: make_list("ge 4.8-r1"), vulnerable: make_list("lt 4.8-r1")
)) { security_warning(0); exit(0); }
