#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net> 
#
#

if(description)
{
 script_id(10107);
 script_version ("$Revision: 1.58 $");
 
 name["english"] = "HTTP Server type and version";
 script_name(english:name["english"]);
 
 desc["english"] = "This detects the HTTP Server's type and version.

Solution: Configure your server to use an alternate name like 
    'Wintendo httpD w/Dotmatrix display'
Be sure to remove common logos like apache_pb.gif.
With Apache, you can set the directive 'ServerTokens Prod' to limit
the information emanating from the server in its response headers.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "HTTP Server type and version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 H. Scholz & Contributors");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_login.nasl", "httpver.nasl", "no404.nasl", "www_fingerprinting_hmap.nasl", "webmin.nasl", "embedded_web_server_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

#
# The script code starts here
#
function get_apache_version()
{
 local_var req, soc, r, v;
 
 req = http_get(item:"/nonexistent_please_dont_exist", port:port);
 soc = http_open_socket(port);
 if(!soc) return NULL;
 send(socket:soc, data:req);
 r = egrep(pattern:"<ADDRESS>.*</ADDRESS>", string:http_recv(socket:soc));
 http_close_socket(soc);
 if(!r)
  return NULL;

 v = ereg_replace(string:r, pattern:"<ADDRESS>(Apache/[^ ]*).*", replace:"\1");
 if( r == v )
  return NULL;
 else return v;
}


function get_domino_version()
{
 local_var req, soc, r, v;
 req = http_get(item:"/nonexistentdb.nsf", port:port);
 soc = http_open_socket(port);
 if(!soc) return NULL;
 send(socket:soc, data:req);
 r = egrep(pattern:".*Lotus-Domino .?Release.*", string:http_recv(socket:soc));
 http_close_socket(soc);
 v = NULL;
 if(r != NULL)v = ereg_replace(pattern:".*Lotus-Domino .?Release ([^ <]*).*", replace:"Lotus-Domino/\1", string:r);
 if(r == NULL || v == r )
  {
   if(get_port_state(25))
   {
    soc = open_sock_tcp(25);
    if(soc)
    {
     r = recv_line(socket:soc, length:4096);
     close(soc);
     v = ereg_replace(pattern:".*Lotus Domino .?Release ([^)]*).*", replace:"Lotus-Domino/\1", string:r);
     if( v == r ) 
       return NULL;
     else 
       return v;
    }
   }
  return NULL;
 }
 else
  return v;
}



 port = get_http_port(default:80);


 if (get_port_state(port))
 {
  soctcp80 = http_open_socket(port);

  if (soctcp80)
  {
   data = http_get(item:"/", port:port);
   resultsend = send(socket:soctcp80, data:data);
   resultrecv = http_recv_headers2(socket:soctcp80);
   if ("Server: " >< resultrecv)
   {
    svrline = egrep(pattern:"^(DAAP-)?Server:", string:resultrecv);
    svr = ereg_replace(pattern:".*Server: (.*)$", string:svrline, replace:"\1");
    report = string("The remote web server type is :\n\n");
    
    if("Apache" >< svr) {
     if("Apache/" >< svr)report = report + svr + string("\n\nSolution : You can set the directive 'ServerTokens Prod' to limit\nthe information emanating from the server in its response headers.");
     else{
       svr2 = get_apache_version();
      if( svr2 != NULL  )
        {
	  report = report + svr2 + string("\n\nThe 'ServerTokens' directive is set to ProductOnly\n",
	  				"however we could determine that the version of the remote\n",
					"server by requesting a non-existent page.\n");
	  svrline = string("Server: ", svr2, "\r\n");
	  if ( defined_func("replace_kb_item") )
	  	replace_kb_item(name:string("www/real_banner/", port), value:svrline);
	  else
	  	set_kb_item(name:string("www/real_banner/", port), value:svrline);
	  if(!get_kb_item("www/banner/" + port))
	  {
	   if ( defined_func("replace_kb_item") )
	  	 replace_kb_item(name:"www/banner/" + port, value:svrline);
	   else
	  	 set_kb_item(name:"www/banner/" + port, value:svrline);
	  }
       }
       else report = report + svr + string("\nand the 'ServerTokens' directive is ProductOnly\nApache does not permit to hide the server type.\n");
     }
    }else{
     if("Lotus-Domino" >< svr)
     {
      if(egrep(pattern:"Lotus-Domino/[1-9]\.[0-9]", string:svr) ) report = report + svr;
      else {
      	svr2 = get_domino_version();
	if( svr2 != NULL )
	{
	 report = report + svr2 + string("\n\nThe product version is hidden but we could determine it by\n",
	 				"requesting a non-existent .nsf file or connecting to port 25\n");
	 svrline = string("Server: ", svr2, "\r\n");
	 if ( defined_func("replace_kb_item") )
	  	replace_kb_item(name:string("www/real_banner/", port), value:svrline);
	 else
	  	set_kb_item(name:string("www/real_banner/", port), value:svrline);
	 if(!get_kb_item("www/banner/" + port))
	  {
	   if ( defined_func("replace_kb_item") )
	  	 replace_kb_item(name:"www/banner/" + port, value:svrline);
	   else
	  	 set_kb_item(name:"www/banner/" + port, value:svrline);
	  }
	}
	 else report = report + svr;
     }
     }
     else 
     {
     report = report + svr;
     }
    }
    security_note(port:port, data:report);
    
    #
    # put the name of the web server in the KB
    #
    if(egrep(pattern:"^Server:.*Domino.*", string:svrline))
    	set_kb_item(name:"www/domino", value:TRUE);

    if(egrep(pattern:"^Server:.*Apache.*", string:svrline))
    	set_kb_item(name:"www/apache", value:TRUE);
	
    if(egrep(pattern:"^Server:.*Apache.* Tomcat/", string:svrline, icase:1))
    	set_kb_item(name:"www/tomcat", value:TRUE);
	
    if(egrep(pattern:"^Server:.*Microsoft.*", string:svrline))
    	set_kb_item(name:"www/iis", value:TRUE);
	
    if(egrep(pattern:"^Server:.*Zope.*", string:svrline))
       set_kb_item(name:"www/zope", value:TRUE);
      
    if(egrep(pattern:"^Server:.*CERN.*", string:svrline))
       set_kb_item(name:"www/cern", value:TRUE);
          
    if(egrep(pattern:"^Server:.*Zeus.*", string:svrline))
       set_kb_item(name:"www/zeus", value:TRUE);
       
     if(egrep(pattern:"^Server:.*WebSitePro.*", string:svrline))
       set_kb_item(name:"www/websitepro", value:TRUE);
       	
    if(egrep(pattern:"^Server:.*NCSA.*", string:svrline))
    	set_kb_item(name:"www/ncsa", value:TRUE);
	
    if(egrep(pattern:"^Server:.*Netscape-Enterprise.*", string:svrline))
    	set_kb_item(name:"www/iplanet", value:TRUE);	
		
    if(egrep(pattern:"^Server:.*Netscape-Administrator.*", string:svrline))
    	set_kb_item(name:"www/iplanet", value:TRUE);	
 
    if(egrep(pattern:"^Server:.*thttpd/.*", string:svrline))
	set_kb_item(name:"www/thttpd", value:TRUE);
	
    if(egrep(pattern:"^Server:.*WDaemon.*", string:svrline))
	set_kb_item(name:"www/wdaemon", value:TRUE);

    if(egrep(pattern:"^Server:.*SAMBAR.*", string:svrline))
	set_kb_item(name:"www/sambar", value:TRUE);
    
    if(egrep(pattern:"^Server:.*IBM-HTTP-Server.*", string:svrline))
	set_kb_item(name:"www/ibm-http", value:TRUE);

    if(egrep(pattern:"^Server:.*Alchemy.*", string:svrline))
	set_kb_item(name:"www/alchemy", value:TRUE);

    if(egrep(pattern:"^Server:.*Rapidsite/Apa.*", string:svrline))
	set_kb_item(name:"www/apache", value:TRUE);

     if(egrep(pattern:"^Server:.*Statistics Server.*", string:svrline))
	set_kb_item(name:"www/statistics-server", value:TRUE);

     if(egrep(pattern:"^Server:.*CommuniGatePro.*", string:svrline))
	set_kb_item(name:"www/communigatepro", value:TRUE);

     if(egrep(pattern:"^Server:.*Savant.*", string:svrline))
	set_kb_item(name:"www/savant", value:TRUE);
    
     if(egrep(pattern:"^Server:.*StWeb.*", string:svrline))
        set_kb_item(name:"www/stweb", value:TRUE);

     if(egrep(pattern:"^Server:.*StWeb.*", string:svrline))
        set_kb_item(name:"www/apache", value:TRUE);
   
     if(egrep(pattern:"^Server:.*Oracle HTTP Server.*", string:svrline))
	set_kb_item(name:"www/OracleApache", value:TRUE);

     if(egrep(pattern:"^Server:.*Oracle HTTP Server.*", string:svrline))
        set_kb_item(name:"www/apache", value:TRUE);

     if(egrep(pattern:"^Server:.*Stronghold.*", string:svrline))
        set_kb_item(name:"www/stronghold", value:TRUE);

     if(egrep(pattern:"^Server:.*Stronghold.*", string:svrline))
        set_kb_item(name:"www/apache", value:TRUE);

     if(egrep(pattern:"^Server:.*MiniServ.*", string:svrline))
        set_kb_item(name:"www/miniserv", value:TRUE);

     if(egrep(pattern:"^Server:.*vqServer.*", string:svrline))
        set_kb_item(name:"www/vqserver", value:TRUE);

     if(egrep(pattern:"^Server:.*VisualRoute.*", string:svrline))
        set_kb_item(name:"www/visualroute", value:TRUE);

     if(egrep(pattern:"^Server:.*Squid.*", string:svrline))
        set_kb_item(name:"www/squid", value:TRUE);

     if(egrep(pattern:"^Server:.*OmniHTTPd.*", string:svrline))
        set_kb_item(name:"www/omnihttpd", value:TRUE);

     if(egrep(pattern:"^Server:.*linuxconf.*", string:svrline))
        set_kb_item(name:"www/linuxconf", value:TRUE);

     if(egrep(pattern:"^Server:.*CompaqHTTPServer.*", string:svrline))
        set_kb_item(name:"www/compaq", value:TRUE);

     if(egrep(pattern:"^Server:.*WebSTAR.*", string:svrline))
        set_kb_item(name:"www/webstar", value:TRUE);

     if(egrep(pattern:"^Server:.*AppleShareIP.*", string:svrline))
        set_kb_item(name:"www/appleshareip", value:TRUE);

     if(egrep(pattern:"^Server:.*Jigsaw.*", string:svrline))
        set_kb_item(name:"www/jigsaw", value:TRUE);

     if(egrep(pattern:"^Server:.*Resin.*", string:svrline))
        set_kb_item(name:"www/resin", value:TRUE);

     if(egrep(pattern:"^Server:.*AOLserver.*", string:svrline))
        set_kb_item(name:"www/aolserver", value:TRUE);

     if(egrep(pattern:"^Server:.*IdeaWebServer.*", string:svrline))
        set_kb_item(name:"www/ideawebserver", value:TRUE);

     if(egrep(pattern:"^Server:.*FileMakerPro.*", string:svrline))
        set_kb_item(name:"www/filemakerpro", value:TRUE);

     if(egrep(pattern:"^Server:.*NetWare-Enterprise-Web-Server.*", string:svrline))
        set_kb_item(name:"www/netware", value:TRUE);

     if(egrep(pattern:"^Server:.*Roxen.*", string:svrline))
        set_kb_item(name:"www/roxen", value:TRUE);

     if(egrep(pattern:"^Server:.*SimpleServer:WWW.*", string:svrline))
        set_kb_item(name:"www/simpleserver", value:TRUE);

     if(egrep(pattern:"^Server:.*Allegro-Software-RomPager.*", string:svrline))
        set_kb_item(name:"www/allegro", value:TRUE);

     if(egrep(pattern:"^Server:.*GoAhead-Webs.*", string:svrline))
        set_kb_item(name:"www/goahead", value:TRUE);

     if(egrep(pattern:"^Server:.*Xitami.*", string:svrline))
        set_kb_item(name:"www/xitami", value:TRUE);

     if(egrep(pattern:"^Server:.*EmWeb.*", string:svrline))
        set_kb_item(name:"www/emweb", value:TRUE);

     if(egrep(pattern:"^Server:.*Ipswitch-IMail.*", string:svrline))
        set_kb_item(name:"www/ipswitch-imail", value:TRUE);

     if(egrep(pattern:"^Server:.*Netscape-FastTrack.*", string:svrline))
        set_kb_item(name:"www/netscape-fasttrack", value:TRUE);

     if(egrep(pattern:"^Server:.*AkamaiGHost.*", string:svrline))
        set_kb_item(name:"www/akamaighost", value:TRUE);

     if(egrep(pattern:"^Server:.*[aA]libaba.*", string:svrline))
        set_kb_item(name:"www/alibaba", value:TRUE);

     if(egrep(pattern:"^Server:.*tigershark.*", string:svrline))
        set_kb_item(name:"www/tigershark", value:TRUE);

     if(egrep(pattern:"^Server:.*Netscape-Commerce.*", string:svrline))
        set_kb_item(name:"www/netscape-commerce", value:TRUE);

     if(egrep(pattern:"^Server:.*Oracle_Web_listener.*", string:svrline))
        set_kb_item(name:"www/oracle-web-listener", value:TRUE);

     if(egrep(pattern:"^Server:.*Caudium.*", string:svrline))
        set_kb_item(name:"www/caudium", value:TRUE);

     if(egrep(pattern:"^Server:.*Communique.*", string:svrline))
        set_kb_item(name:"www/communique", value:TRUE);

     if(egrep(pattern:"^Server:.*Cougar.*", string:svrline))
        set_kb_item(name:"www/cougar", value:TRUE);

     if(egrep(pattern:"^Server:.*FirstClass.*", string:svrline))
        set_kb_item(name:"www/firstclass", value:TRUE);

     if(egrep(pattern:"^Server:.*NetCache.*", string:svrline))
        set_kb_item(name:"www/netcache", value:TRUE);

     if(egrep(pattern:"^Server:.*AnWeb.*", string:svrline))
        set_kb_item(name:"www/anweb", value:TRUE);

     if(egrep(pattern:"^Server:.*Pi3Web.*", string:svrline))
        set_kb_item(name:"www/pi3web", value:TRUE);

     if(egrep(pattern:"^Server:.*TUX.*", string:svrline))
        set_kb_item(name:"www/tux", value:TRUE);

     if(egrep(pattern:"^Server:.*Abyss.*", string:svrline))
        set_kb_item(name:"www/abyss", value:TRUE);

     if(egrep(pattern:"^Server:.*BadBlue.*", string:svrline))
        set_kb_item(name:"www/badblue", value:TRUE);

     if(egrep(pattern:"^Server:.*WebServer 4 Everyone.*", string:svrline))
        set_kb_item(name:"www/webserver4everyone", value:TRUE);

     if(egrep(pattern:"^Server:.*KeyFocus Web Server.*", string:svrline))
        set_kb_item(name:"www/KFWebServer", value:TRUE);

     if(egrep(pattern:"^Server:.*Jetty.*", string:svrline))
        set_kb_item(name:"www/jetty", value:TRUE);
	
     if(egrep(pattern:"^Server:.*bkhttp/.*", string:svrline))
        set_kb_item(name:"www/BitKeeper", value:TRUE);	

     if(egrep(pattern:"^Server:.*CUPS/.*", string:svrline))
        set_kb_item(name:"www/cups", value:TRUE);	

     if(egrep(pattern:"^Server:.*WebLogic.*", string:svrline))
     	set_kb_item(name:"www/weblogic", value:TRUE);

     if(egrep(pattern:"^Server:.*Novell-HTTP-Server.*", string:svrline))
       	set_kb_item(name:"www/novell", value:TRUE);
	
     if(egrep(pattern:"^Server:.*theServer/.*", string:svrline))
       	set_kb_item(name:"www/theserver", value:TRUE);

     if(egrep(pattern:"^Server:.*WWW File Share.*", string:svrline))
        set_kb_item(name:"www/wwwfileshare", value:TRUE);
 
	
   #  if(!egrep(pattern:"^Server:.*", string:svrline))
   #     set_kb_item(name:"www/none", value:TRUE);
   } 
  close(soctcp80);
  }
 }
