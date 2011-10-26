#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10041);
 script_bugtraq_id(1238, 777);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-1530", "CVE-2000-0431");


 name["english"] = "Cobalt RaQ2 cgiwrap";
 name["francais"] = "Cobalt RaQ2 cgiwrap";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "
'cgiwrap' is installed. If you are running an unpatched Cobalt RaQ, 
the version of cgiwrap distributed with that system has a known
security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

This flaw exists only on the Cobalt modified cgiwrap. Standard builds
of cgiwrap are not affected.

Solution : upgrade your Cobalt RaQ to apply fix
Risk factor : Medium";




 script_description(english:desc["english"]);

 summary["english"] = "Checks for the presence of /cgi-bin/cgiwrap";
 summary["francais"] = "Vérifie la présence de /cgi-bin/cgiwrap";
   
 script_summary(english:summary["english"], francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 1999 Mathieu Perrin",
         francais:"Ce script est Copyright (C) 1999 Mathieu Perrin");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}	  
  
#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"cgiwrap", port:port);
if(res)security_warning(port);

   
