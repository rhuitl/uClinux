#
# This script was written by Renaud Deraison <deraison@nessus.org>
# 
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11450);
 script_version ("$Revision: 1.1 $");

 script_cve_id("CVE-2001-0456");
 
 name["english"] = "Debian proftpd 1.2.0 runs as root";
 
 script_name(english:name["english"]);
             
 desc["english"] = "
The following problems have been reported for the version of proftpd in 
Debian 2.2 (potato):

   1. There is a configuration error in the postinst script, when the user 
      enters 'yes', when asked if anonymous access should be enabled. 
      The postinst script wrongly leaves the 'run as uid/gid root' 
      configuration option in /etc/proftpd.conf, and adds a 
      'run as uid/gid nobody' option that has no effect.
      
   2. There is a bug that comes up when /var is a symlink, and 
       proftpd is restarted. When stopping proftpd, the /var 
       symlink is removed; when it's started again a file named 
       /var is created. 
       
       
See also : http://www.debian.org/security/2001/dsa-032
Solution : Upgrade your proftpd server to proftpd-1.2.0pre10-2.0potato1
Risk factor : Medium";
                 
                     
 script_description(english:desc["english"]);
                    
 
 script_summary(english:"Checks if the version of the remote proftpd",
                francais:"Détermine la version du proftpd distant");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
                  
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#



include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);

if(egrep(pattern:"^220 ProFTPD 1\.(0\.*|2\.0pre([0-9][^0-9]|10)).*debian.*", string:banner, icase:TRUE))security_warning(port);

