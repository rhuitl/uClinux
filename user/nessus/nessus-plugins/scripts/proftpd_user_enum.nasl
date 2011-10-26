#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: LSS Security
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15484);
 script_version ("$Revision: 1.4 $");
 script_bugtraq_id(11430);
 script_cve_id ("CVE-2004-1602");
 
 name["english"] = "proftpd < 1.2.11 remote user enumeration";
 
 script_name(english:name["english"]);
             
 desc["english"] = "
The remote ProFTPd server is as old or older than 1.2.10

It is possible to determine which user names are valid on the remote host 
based on timing analysis attack of the login procedure.

An attacker may use this flaw to set up a list of valid usernames for a
more efficient brute-force attack against the remote host.

Solution : Upgrade to a newer version
Risk factor : Low";
                 
                 
                     
 script_description(english:desc["english"]);
                    
 
 script_summary(english:"Checks the version of the remote proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP", francais:"FTP");

 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
                  
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);
if(egrep(pattern:"^220 ProFTPD 1\.2\.([0-9][^0-9]|10[^0-9])", string:banner))
{
  security_warning(port);
}
