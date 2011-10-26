# -*- Fundamental -*-
#
# 
# (C) 2005 Tenable Network Security
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# dns_func.inc 
# $Revision: 1.4 $
#

dns_struct = make_list("transaction_id",
		       "flags",
			"q",
			"an_rr",
			"au_rr",
			"ad_rr");


dns_sizes = make_array("transaction_id",     16,
			"flags",	     16,
			"q",		     16,
			"an_rr",	     16,
			"au_rr",	     16,
			"ad_rr",	     16);


function get_query_txt()
{
 local_var s, l;
 s = _FCT_ANON_ARGS[0];
 if ( isnull(s) ) return NULL;
 l = ord(s[0]);
 return substr(s, 1, l);
}



function mk_query_txt()
{
 local_var i, ret;
 for ( i = 0 ; _FCT_ANON_ARGS[i] ; i ++ )
 {
   ret += raw_string(strlen(_FCT_ANON_ARGS[i])) + _FCT_ANON_ARGS[i];
 }
 return ret + raw_string(0);
}

function mk_query(txt, type, class)
{
 return txt + raw_string(type << 16,  type & 0xff, class << 16, class & 0xff); 
}

function mkdns(dns, query)
{
 local_var item, ret;
 foreach item ( dns_struct )
 {
  ret += raw_string(dns[item] << 16, dns[item] & 0xff);
 }

 return ret + query;
}




function dns_comp_get(str, offset, rec)
{
 local_var i, o, l, ret;

 if ( ! rec ) rec = 0;
 if ( rec > 2 ) exit(0);

 o = offset;

 while ( TRUE )
 {
  l = ord(str[o]);
  if ( (l & 0xc0) == 0xc0 ) {
	o = ord(str[o+1]);
	ret += dns_comp_get(str:str, offset:o, rec:rec+1);
	break;
	}
  else
  {
   if ( o + l > strlen(str) ) return NULL;
   ret += substr(str, o + 1, o + l);
   if ( ord(str[o+l]) == 0 ) break;
   else ret += '.';
   o += l + 1;
  }
 }
 return ret;
}

function dns_str_get(str, blob)
{
 local_var ret, l, offset;

 offset = 0;
 while ( TRUE )
 {
  if ( ( ord(str[offset]) & 0xc0 ) == 0xc0 ) 
	{
	offset = ord(str[offset+1]);
	if ( ret ) return ret + '.' + dns_comp_get(str:blob, offset:offset);
	else return dns_comp_get(str:blob, offset:offset);
	}
   
   l = ord(str[offset]);
   if ( offset + l > strlen(str) ) return ret;
   ret += substr(str, offset + 1, offset + l ); 
   if ( ord(str[offset+l]) == 0 ) break;
   offset += l + 1;
 }
 return ret;
}


function dns_split()
{
 local_var ret, n, m, item, ptr, p, cur, t, l;
 local_var names, offset, i, tmp, o;


 if ( isnull(_FCT_ANON_ARGS[0])) exit(0);
 p   = _FCT_ANON_ARGS[0];

 ptr = 0;
 foreach item ( dns_struct )
 {
  if ( ptr >= strlen(p) ) return NULL;
  ret[item] = getword(blob:p, pos:ptr);
  ptr += 2;
 }

 foreach item ( make_list("q", "an_rr", "au_rr", "ad_rr") )
 {
  for ( n = 0 ; n < ret[item] ; n ++ )
  {
   cur = item + "_data_" + n;
   while ( TRUE )
   {
    if ( ptr >= strlen(p) ) return ret;
    m = ord(p[ptr]);
    if ( (m & 0xc0) == 0xc0 ) # Compression
     {
      t = dns_comp_get(str:p, offset:ptr);
      ptr ++;
      m  = 0;
     }

    if ( m == 0 ) {
		ptr ++;
		ret[cur + "_name"] = t;
		if ( ptr + 2 >= strlen(p) ) break;
		ret[cur + "_type"] = getword(blob:p, pos:ptr);
		ptr += 2;
		if ( ptr + 2 >= strlen(p) ) break;
		ret[cur + "_class"] = getword(blob:p, pos:ptr);
		ptr += 2;
		if ( item != "q" )
		{
		 if ( ptr >= strlen(p) ) break;
		 ret[cur + "_ttl"] = getdword(blob:p, pos:ptr);
		 ptr += 4;
		 if ( ptr + 4>= strlen(p) ) break;
		 l = getword(blob:p, pos:ptr);
		 ptr += 2;
		 ret[cur + "_data"] = substr(p, ptr, ptr + l - 1);
		 ptr += l;
		}
		t = NULL;
		break;   
	}
    else {
	 if ( t ) t += ".";
	 else offset = ptr;

	 ptr ++;
	 t += substr(p, ptr,ptr +  m - 1);
	 ptr = ptr + m;
	}
    }
  }
 }

 return ret;
}
