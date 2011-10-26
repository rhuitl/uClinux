#
# Written by Renaud Deraison <deraison@nessus.org>
#



if(description)
{
 script_id(11422);
 script_version ("$Revision: 1.16 $");
 name["english"] = "Unconfigured web server";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Remote web server is not or badly configured

Description :

The remote web server seems to have its default welcome page set.
It probably means that this server is not used at all.

Solution :

Disable this service, as you do not use it

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the remote web server has been configured";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
req = http_get_cache(item:"/", port:port);
if(req == NULL) exit(0);

req = tolower(req);

#
# Apache
# 
apache_head = "<title>test page for apache installation</title>";
apache_body = "<p>this page is here because the site administrator has changed the
configuration of this web server. please <strong>contact the person
responsible for maintaining this server with questions.</strong>
the apache software foundation, which wrote the web server software
this site administrator is using, has nothing to do with
maintaining this site and cannot help resolve configuration
issues.</p>";

if(apache_head >< req && apache_body >< req){security_note(port);exit(0);}


apache_head = "<title>test page for the apache web server on red hat linux</title>";
apache_body = "this page is used to test the proper operation of the apache web server after";

if(apache_head >< req && apache_body >< req){security_note(port);exit(0);}


if(egrep(pattern:"<title>test page for .*apache installation on web site</title>",
         string:req)){security_note(port);exit(0);}


if("<title>test page for the apache http server on fedora core</title>" >< req)
{
 security_note(port);
 exit(0);
}


#
# IIS
#
iis_head = "<title id=titletext>under construction</title>";
iis_body = "the site you were trying to reach does not currently have a default page. it may be in the process of being upgraded.";

if(iis_head >< req && iis_body >< req){ security_note(port); exit(0); }

#
# IIS 4.0 (NT Server Option Pack)
#
ntoptionpack_head = "Welcome To IIS 4.0";
ntoptionpack_body = "Microsoft Windows NT 4.0 Option Pack";

if(ntoptionpack_head >< req && ntoptionpack_body >< req){ security_note(port); exit(0); }

#
# Domino 6.0
# 

domino_head = 'body text="#000000" bgcolor="#000000" style="background-image:url(/homepage.nsf/homepage.gif?openimageresource); background-repeat: no-repeat; ">';
domino_body = "/help/help6_client.nsf";

if(domino_head >< req && domino_body >< req){security_note(port); exit(0); }


#
# iPlanet 6.0
# 

iplanet_head = "<title>iplanet web server, enterprise edition 6.0</title>";
iplanet_body = '<frame name="banner" src="banner.html" scrolling="no">';


if(iplanet_head >< req && iplanet_body >< req){security_note(port); exit(0); }


#
# Sambar
# 

sambar_head = "<title>sambar server</title>";
sambar_body = "<b>pro server features<b>";
if(sambar_head >< req){security_note(port); exit(0);}


#
# NetWare 6.0
#

netware_head = "<title>welcome to netware 6</title>";
netware_body = '<frame name="branding" marginwidth="7" marginheight="0" src="brand.html" noresize scrolling="no">';
if (netware_head >< req && netware_body >< req ){security_note(port); exit(0);}


#
# BEA WebLogic Server 7.0 (thanks to Simon Ward <simon@westpoint.ltd.uk>)
#
beaweblogic_head = "<title>read me - welcome to bea weblogic server</title>";
beaweblogic_body = "welcome to bea weblogic server";
if(beaweblogic_head >< req && beaweblogic_body >< req){ security_note(port); exit(0); }
