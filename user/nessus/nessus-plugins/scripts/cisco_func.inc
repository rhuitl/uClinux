#
# (C) Tenable Network Security
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

if ( NASL_LEVEL < 2191 ) exit(0);

function extract_version()
{
 local_var ret;
 ret = ereg_replace(pattern:".*.*Version ([0-9.]*\([0-9a-z]*\)[A-Z]*[0-9]*),.*",
	            replace:"\1",
		    string:_FCT_ANON_ARGS[0]);

 return ret;
}



function cmpv()
{
 local_var a,b,i,min;

 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];

 if ( ereg(pattern:"^[0-9]*$", string:a) && ereg(pattern:"^[0-9]*$", string:b) )
	{
	return int(a) - int(b);
	}


 min = strlen(a);
 if ( strlen(b) < min )
	min = strlen(b);

 for ( i = 0 ; i < min ; i ++ )
 {
  if ( ord(a[i]) != ord(b[i]) )
	return ord(a[i]) - ord(b[i]);
 }
 if ( strlen(a) > min ) 
	return 1;
 else if ( strlen(b) > min )
	return -1;
 else 
	return 0;
}

function cmp_build()
{
 local_var a, b, s1, s2;
 local_var array1, array2;
 local_var n, i;


 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 s1 = ereg_replace(pattern:"[0-9.]*\([0-9a-z]*\)([A-Z]*[0-9]*)", string:a, replace:"\1");
 s2 = ereg_replace(pattern:"[0-9.]*\([0-9a-z]*\)([A-Z]*[0-9]*)", string:b, replace:"\1");
 
 array1 = split(s1, sep:'.', keep:0);
 array2 = split(s2, sep:'.', keep:0);
 n = max_index(array1);

 for ( i = 0 ; i < n ; i ++ )
 {
  if ( array1[i] != array2[i] )
	return cmpv(array1[i], array2[i]);
 }
 return 0;
}



function cmp_release()
{
 local_var a, b, s1, s2;
 local_var array1, array2;
 local_var n, i;


 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 s1 = ereg_replace(pattern:"[0-9.]*\(([0-9a-z]*)\)[A-Z]*[0-9]*", string:a, replace:"\1");
 s2 = ereg_replace(pattern:"[0-9.]*\(([0-9a-z]*)\)[A-Z]*[0-9]*", string:b, replace:"\1");
 
 array1 = split(s1, sep:'.', keep:0);
 array2 = split(s2, sep:'.', keep:0);
 n = max_index(array1);

 for ( i = 0 ; i < n ; i ++ )
 {
  if ( array1[i] != array2[i] )
	return cmpv(array1[i], array2[i]);
 }
 return 0;
}



function cmp_version()
{
 local_var a, b, s1, s2, b1, b2;
 local_var array1, array2;
 local_var n, i;


 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 s1 = ereg_replace(pattern:"([0-9.]*)\([0-9a-z]*\)[A-Z]*[0-9]*", string:a, replace:"\1");
 s2 = ereg_replace(pattern:"([0-9.]*)\([0-9a-z]*\)[A-Z]*[0-9]*", string:b, replace:"\1");
 b1 = ereg_replace(pattern:"[0-9.]*\([0-9a-z]*\)([A-Z]*)[0-9]*", string:a, replace:"\1");
 b2 = ereg_replace(pattern:"[0-9.]*\([0-9a-z]*\)([A-Z]*)[0-9]*", string:b, replace:"\1");

 if ( b1 != b2 )
	return -1;
 
 array1 = split(s1, sep:'.', keep:FALSE);
 array2 = split(s2, sep:'.', keep:FALSE);
 n = max_index(array1);

 for ( i = 0 ; i < n ; i ++ )
 {
  if ( array1[i] != array2[i] )
	return cmpv(array1[i], array2[i]);
 }

 return 0;
}

function check_release(version, patched, newest, oldest)
{
 local_var v, n, r;
 local_var vulnerable, not_vulnerable;

 vulnerable = 0;
 not_vulnerable = 0;

 for ( n = 0; n < max_index(patched) ; n ++ )
 {
  v = patched[n];
  r = cmp_version(version, v);
  if ( r == 0 )
	{
	 r = cmp_release(version, v);
  	 if ( r < 0 )
		{
		 vulnerable = 1;
		}	
	 else
		{
		 r = cmp_build(version ,v);
		 if ( r < 0 ) vulnerable = 1;
		 else not_vulnerable = 1;
		}
	}
   else vulnerable = 0;  # Useless?
 }

 # We've checked all the branches, now check the newest release
 if ( vulnerable && ! not_vulnerable )
	{
	if ( 
		cmp_version(version, newest) == 0 &&
	 	(	cmp_release(version, newest) < 0 ||
	   	(       cmp_release(version, newest) == 0 && cmp_build(version, newest) < 0 ) ) 
	   )
		{
		 if ( ! isnull(oldest) )
		 {
		  if ( cmp_version(oldest, version) == 0 &&
		      ( cmp_release(oldest, version) > 0 ||
		      ( cmp_release(oldest, version) == 0 && cmp_build(oldest, version) > 0 ) ) )
		 	return 0;
		 }
		return 1;
		}
	else
		return 0;
	}
 else
	return 0;
}



function deprecated_version()
{
 local_var array,s,n;
 array = eregmatch(pattern:"([0-9.]*)\([0-9a-z]*\)([A-Z]*)[0-9]*", string:_FCT_ANON_ARGS[0]);
 s = string(array[1], array[2]);

 for ( n = 1 ; _FCT_ANON_ARGS[n] ; n ++ )
 {
  if ( s == _FCT_ANON_ARGS[n] )
	return 1; 
 }

 return 0;
}


#if (check_release(version:"12.3(7f)T0", fixed_releases:make_list("12.3(7)T6", "12.3(5)T6"), newest_release:"12.3(7d)T1") )
#	{
#	 display("VUNERABLE\n");
#}

