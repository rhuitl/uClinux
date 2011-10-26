#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref : Hobbit <hobbit@avian.org>
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14599);
 script_bugtraq_id(6050, 6051);
 script_version ("$Revision: 1.6 $");
 name["english"] = "WS FTP server FTP bounce attack and PASV connection hijacking flaws";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
According to its version number, the remote WS_FTP server is vulnerable
to session hijacking during passive connections and to an FTP bounce 
attack when a user submits a specially crafted FTP command.

** Nessus only checked the version number in the server banner

Solution : Upgrade to the latest version of this software
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

#now the code

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if (egrep(pattern:"WS_FTP Server ([0-2]\.|3\.(0\.|1\.[0-3][^0-9]))", string: banner))
	security_hole(port);
