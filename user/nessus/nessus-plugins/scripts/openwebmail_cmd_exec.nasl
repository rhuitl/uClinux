#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Modified by Xue Yong Zhi(xueyong@udel.edu) to check OpenWebmail banner
#
# See the Nessus Scripts License for details
#
#
# As for bugtrapid 6425, a successful attack requires attacker to be able 
# to put 2 files on target system.
#
# Reference: 
# [1] http://www.securityfocus.com/archive/1/300834 
# [2] http://www.securityfocus.com/archive/1/303997
# [3] http://openwebmail.org/openwebmail/download/cert/advisories/SA-02:01.txt
#

if(description)
{
 script_id(11416);
 script_bugtraq_id(6232, 6425);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2002-1385");
 name["english"] = "openwebmail command execution";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running an old version of OpenWebMail 
which allows users to execute arbitrary commands on
the remote host with the superuser permissions. It also
has user name information disclosure problem.

Solution : Upgrade to OpenWebMail 1.90 or newer
Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Determines the version of openwebmail";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl" );
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


foreach d (cgi_dirs())
{
  # UGLY UGLY UGLY
  req = http_get(item:string(d, "/openwebmail/openwebmail.pl"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  #Banner example:
  #<a href="http://openwebmail.org/openwebmail/" target="_blank">Open WebMail</a>
  #version 1.81
  # &nbsp;
 
  if("Open WebMail" >< res)
  {
    if(egrep(pattern:".*version.*1\.([0-7][0-9]|80|81)", string:res))
    security_warning(port);
  }
 
}
