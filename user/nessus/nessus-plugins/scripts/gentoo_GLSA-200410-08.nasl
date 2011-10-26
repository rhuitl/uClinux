# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15446);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-08
(ncompress: Buffer overflow)


    compress and uncompress do not properly check bounds on command line
    options, including the filename. Large parameters would trigger a buffer
    overflow.
  
Impact

    By supplying a carefully crafted filename or other option, an attacker
    could execute arbitrary code on the system. A local attacker could only
    execute code with his own rights, but since compress and uncompress are
    called by various daemon programs, this might also allow a remote attacker
    to execute code with the rights of the daemon making use of ncompress.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.kb.cert.org/vuls/id/176363


Solution: 
    All ncompress users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-arch/ncompress-4.2.4-r1"
    # emerge ">=app-arch/ncompress-4.2.4-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-08] ncompress: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ncompress: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/ncompress", unaffected: make_list("ge 4.2.4-r1"), vulnerable: make_list("le 4.2.4")
)) { security_warning(0); exit(0); }
