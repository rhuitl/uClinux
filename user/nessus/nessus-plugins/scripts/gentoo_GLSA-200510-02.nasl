# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19822);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200510-02");
 script_cve_id("CVE-2005-3115");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-02
(Berkeley MPEG Tools: Multiple insecure temporary files)


    Mike Frysinger of the Gentoo Security Team discovered that
    mpeg_encode and the conversion utilities were creating temporary files
    with predictable or fixed filenames. The \'test\' make target of the MPEG
    Tools also relied on several temporary files created insecurely.
  
Impact

    A local attacker could create symbolic links in the temporary
    files directory, pointing to a valid file somewhere on the filesystem.
    When the utilities are executed (or \'make test\' is run), this would
    result in the file being overwritten with the rights of the user
    running the command.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3115


Solution: 
    All Berkeley MPEG Tools users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/mpeg-tools-1.5b-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-02] Berkeley MPEG Tools: Multiple insecure temporary files");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Berkeley MPEG Tools: Multiple insecure temporary files');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/mpeg-tools", unaffected: make_list("ge 1.5b-r2"), vulnerable: make_list("lt 1.5b-r2")
)) { security_warning(0); exit(0); }
