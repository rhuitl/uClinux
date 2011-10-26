# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17288);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-14");
 script_cve_id("CVE-2005-0365");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-14
(KDE dcopidlng: Insecure temporary file creation)


    Davide Madrisan has discovered that the dcopidlng script creates
    temporary files in a world-writable directory with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary
    files directory, pointing to a valid file somewhere on the filesystem.
    When dcopidlng is executed, this would result in the file being
    overwritten with the rights of the user running the utility, which
    could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0365


Solution: 
    All kdelibs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdelibs
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-14] KDE dcopidlng: Insecure temporary file creation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDE dcopidlng: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("ge 3.3.2-r5", "rge 3.2.3-r7"), vulnerable: make_list("lt 3.3.2-r5")
)) { security_warning(0); exit(0); }
