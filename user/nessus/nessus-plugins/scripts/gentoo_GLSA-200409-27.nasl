# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-27.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14790);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200409-27");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-27
(glFTPd: Local buffer overflow vulnerability)


    The glFTPd server is vulnerable to a buffer overflow in the \'dupescan\'
    program. This vulnerability is due to an unsafe strcpy() call which can
    cause the program to crash when a large argument is passed.
  
Impact

    A local user with malicious intent can pass a parameter to the dupescan
    program that exceeds the size of the buffer, causing it to overflow. This
    can lead the program to crash, and potentially allow arbitrary code
    execution with the permissions of the user running glFTPd, which could be
    the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/375775/2004-09-17/2004-09-23/0
    http://www.glftpd.com/modules.php?op=modload&name=News&file=article&sid=23&mode=thread&order=0&thold=0


Solution: 
    All glFTPd users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-ftp/glftpd-1.32-r1"
    # emerge ">=net-ftp/glftpd-1.32-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-27] glFTPd: Local buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'glFTPd: Local buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-ftp/glftpd", unaffected: make_list("ge 1.32-r1"), vulnerable: make_list("lt 1.32-r1")
)) { security_warning(0); exit(0); }
