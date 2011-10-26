#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref : Hugh Mann <hughmann@hotmail.com>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14598);
 script_cve_id(
   "CVE-2004-1848",
   "CVE-2004-1883",
   "CVE-2004-1884",
   "CVE-2004-1885",
   "CVE-2004-1886"
 );
 script_bugtraq_id(9953);
 script_version ("$Revision: 1.7 $");
 name["english"] = "WS FTP server multiple flaws";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
According to its version number, the remote WS_FTP server is vulnerable to 
multiple flaws.

- A buffer overflow, caused by a vulnerability in the ALLO handler, an
attacker can then execute arbitrary code

- A flaw which allow an attacker to gain elevated privileges (SYSTEM level privileges)

- A local or remote attacker, with write privileges on a directory can create a
specially crafted file containing a large REST argument and resulting to a denial
of service

** Nessus only checked the version number in the server banner.

Solution : Upgrade to the latest version of this software.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check WS_FTP server version";
  script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if (egrep(pattern:"WS_FTP Server ([0-3]\.|4\.0[^0-9.]|4\.0\.[12][^0-9])", string: banner))
	security_hole(port);
