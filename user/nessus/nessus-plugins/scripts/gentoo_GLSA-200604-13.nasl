# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21278);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200604-13");
 script_cve_id("CVE-2006-1695");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200604-13
(fbida: Insecure temporary file creation)


    Jan Braun has discovered that the "fbgs" script provided by fbida
    insecurely creates temporary files in the "/var/tmp" directory.
  
Impact

    A local attacker could create links in the temporary file
    directory, pointing to a valid file somewhere on the filesystem. When
    an affected script is called, this could result in the file being
    overwritten with the rights of the user running the script.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1695


Solution: 
    All fbida users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/fbida-2.03-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200604-13] fbida: Insecure temporary file creation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'fbida: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/fbida", unaffected: make_list("ge 2.03-r3"), vulnerable: make_list("lt 2.03-r3")
)) { security_warning(0); exit(0); }
