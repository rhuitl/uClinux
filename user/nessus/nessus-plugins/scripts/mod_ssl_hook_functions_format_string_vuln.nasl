#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# ref: mod_ssl team July 2004
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(13651);
 script_version("$Revision: 1.12 $");
 
 script_cve_id("CVE-2004-0700");
 script_bugtraq_id(10736);
 script_xref(name:"OSVDB", value:"7929");

 name["english"] = "mod_ssl hook functions format string vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version vulnerable of mod_ssl which is
older than 2.8.19. There is a format string condition in the
log functions of the remote module which may allow an attacker to
execute arbitrary code on the remote host.

*** Some vendors patched older versions of mod_ssl, so this
*** might be a false positive. Check with your vendor to determine
*** if you have a version of mod_ssl that is patched for this 
*** vulnerability

Solution : Upgrade to version 2.8.19 or newer
Risk factor : High";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of mod_ssl";
 summary["francais"] = "Vérifie la version de mod_ssl";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 if ( defined_func("bn_random") ) 
 	script_dependencie("redhat-RHSA-2004-408.nasl", "mandrake_MDKSA-2004-075.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include('backport.inc');

if ( get_kb_item("CVE-2004-0700") ) exit(0);

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_backport_banner(banner:get_http_banner(port:port));
 if(!banner)exit(0);
 if ( "Darwin" >< banner )exit(0);

 serv = strstr(banner, "Server");
 if("Apache/" >!< serv ) exit(0);
 if("Apache/2" >< serv) exit(0);
 if("Apache-AdvancedExtranetServer/2" >< serv)exit(0);

 if(ereg(pattern:".*mod_ssl/(1.*|2\.([0-7]\..*|8\.([0-9]|1[0-8])[^0-9])).*", string:serv))
 {
   security_hole(port);
 }
}
