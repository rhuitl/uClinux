# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19820);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200509-21");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-21
(Hylafax: Insecure temporary file creation in xferfaxstats script)


    Javier Fernandez-Sanguino has discovered that xferfaxstats cron
    script supplied by Hylafax insecurely creates temporary files with
    predictable filenames.
  
Impact

    A local attacker could create symbolic links in the temporary file
    directory, pointing to a valid file somewhere on the filesystem. When
    the xferfaxstats script of Hylafax is executed, this would result in
    the file being overwritten with the rights of the user running the
    script, which typically is the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=329384


Solution: 
    All Hylafax users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-misc/hylafax
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-21] Hylafax: Insecure temporary file creation in xferfaxstats script");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Hylafax: Insecure temporary file creation in xferfaxstats script');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/hylafax", unaffected: make_list("rge 4.2.0-r3", "rge 4.2.1-r2", "ge 4.2.2"), vulnerable: make_list("lt 4.2.2")
)) { security_warning(0); exit(0); }
