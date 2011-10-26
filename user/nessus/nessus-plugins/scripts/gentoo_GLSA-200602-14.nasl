# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20980);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-14
(noweb: Insecure temporary file creation)


    Javier Fernandez-Sanguino has discovered that the lib/toascii.nw
    and shell/roff.mm scripts insecurely create temporary files with
    predictable filenames.
  
Impact

    A local attacker could create symbolic links in the temporary file
    directory, pointing to a valid file somewhere on the filesystem. When
    an affected script is called, this would result in the file being
    overwritten with the rights of the user running the script.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3342


Solution: 
    All noweb users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/noweb-2.9-r5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-14] noweb: Insecure temporary file creation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'noweb: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/noweb", unaffected: make_list("ge 2.9-r5"), vulnerable: make_list("lt 2.9-r5")
)) { security_warning(0); exit(0); }
