/* STP - Simple Time Protocol - This program makes the uCsimm contact the US National Institute of Technology(NIST) and get the current time via the Internet.  This program uses no non-standard libraries.
Programming by Joe Lang Lang@thunder.nws.noaa.gov and systems analysis and complaining by Pat Stingley stingley@cpcug.org

Completion date 3-14-00

Daytime Protocol Usage: stp [minutes west of Zulu][DST - yes/no]
*/


#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PROGRAM_NAME "stp"

#define TRUE 1
#define FALSE 0

#define CHAR_NULL ((char *) NULL)
#define NULL_CHAR '\0'

#define ADDR_CAST (struct sockaddr *)

#define NO_HOST_INFO -1
#define NO_SERVICE_INFO -2
#define NO_CONNECT -3
#define BAD_DATA_SIZE -4
#define NO_SOCKET -5
#define NOT_HEALTHY -6
#define INCOMPLETE_DATA -7

#define SPM 60 /* Seconds Per Minute */
#define SPH 3600 /* Seconds Per Hour */

/* Function prototypes. */
int DayTimeProtocol( char *nist_time_host, struct timeval *tv_ptr,
                     struct timezone *tz_ptr, int minutes_west, int use_dst );

int lc_client( char *the_host, char *the_service,
               char *the_protocol, int *sd_ptr );

int lc_connect( int sd, struct hostent *hp, struct servent *sp );

int lc_get_host_info( char *host_name, struct hostent **hpp );

int lc_get_service_info( char *service, char *protocol, struct servent **spp );

int lc_socket( int *sd_ptr, int socket_type );

int lc_read_data( int sd, void *data, int max_bytes );

/* Static/global variables for recording errors. */
static int g_error; /* global error number variable for the stp program */
static char g_error_msg[BUFSIZ]; /* global error message buffer for the stp program */

/* NIST Time Hosts. */
static char *nist_time_hosts[] =
{
"time-a.nist.gov",
"time-b.nist.gov",
"time-a.timefreq.bldrdoc.gov",
"time-b.timefreq.bldrdoc.gov",
"time-c.timefreq.bldrdoc.gov",
"utcnist.colorado.edu",
"time.nist.gov",
"time-nw.nist.gov",
"nist1.dc.certifiedtime.com",
"nist1.datum.com",
"nist1.nyc.certifiedtime.com",
"nist1.sjc.certifiedtime.com",
CHAR_NULL
};

int main( int argc, char *argv[] )
{
char host_name[BUFSIZ];
struct timeval tv;
struct timezone tz;
int minutes_west;
int use_dst; /* Indicates if we should use DST if applicable. */
int i; /* loop variable */
int rv; /* return value (rv) variable */
char *minutes_west_argument;
int valid_minutes_west_argument;
int got_nist_time;
int the_time_was_set;
time_t current_time_in_seconds;

/* Determine the name  of our host. */
   gethostname( host_name, sizeof( host_name ) );

/* Process the command line. */
   switch ( argc )
   {

      case 1: /* command line: stp --- defaulting to GMT/UTC. */

         minutes_west = 0; /* Default to GMT */

         use_dst = FALSE; /* The default is not to use DST. */

         break;

      case 2: /* command line: stp minuteswest */
      case 3: /* command line: stp minuteswest yes_or_no */

/* Point to the argument that specifies the minutes west. */
          minutes_west_argument = argv[1];

/* Scan the minutes west argument for the specified minutes west value. */
         rv = sscanf( minutes_west_argument, "%d", &minutes_west );

         valid_minutes_west_argument = (rv == 1);

         if ( ! valid_minutes_west_argument )
         {

            fprintf( stderr, "Invalid value [%s] forMinutesWest.\n",
                     minutes_west_argument );

            exit( 1 );

         }

/* Was the yes/no DST value specified? */
         if ( argc == 3 )
         {
            rv = strcasecmp( argv[2], "no" );
            use_dst = (rv != 0); /* argv[2] did not equal "no" */
         }
         else use_dst = TRUE; /* The default is to use DST if minutes west is provided. */

         break;

      default:

         fprintf( stderr, "Error In Usage!\n" );

         fprintf( stderr, "Proper Usage: %s MinutesWest [yes] or [no]\n",
                  PROGRAM_NAME );

         exit( 0 );

         break;

   } /* switch ( argc ) */

/* Find a NIST host to supply us with the current UTC time. */
   for (i = 0; nist_time_hosts[i] != CHAR_NULL; i++)
   {

      rv = DayTimeProtocol( nist_time_hosts[i], &tv,&tz,
                            minutes_west, use_dst );

      got_nist_time = (rv == 0);

      if ( got_nist_time ) break;

   } /* for ( i ) */

   if ( ! got_nist_time )
   {
      fprintf( stderr, "No NIST Time!\n" );
      fprintf( stderr,  "%s\n", g_error_msg );
      exit( 1 );
   }

   printf( "%s received the time from: %s  Server #%d\n",
           host_name, nist_time_hosts[i], i + 1 );

/* Must be the super user (root) to successfully execute settimeofday(). */
   rv = settimeofday( &tv, &tz );

   the_time_was_set = (rv == 0);

   if ( ! the_time_was_set )
   {
      perror( "settimeofday()" );
      exit( 1 );
   }

/* Display the current system time. */
   time( &current_time_in_seconds );

   printf( "The System Time: %s", ctime( &current_time_in_seconds ) );

   return 0;
} /* main() */


int DayTimeProtocol( char *nist_time_host, struct timeval *tv_ptr,
                     struct timezone *tz_ptr, int minutes_west, int use_dst )
{
int sd; /* socket descriptor */
int rv; /* return value (rv) variable */
int offset;
char c;
char buf[BUFSIZ];
long modified_julian_day; /* read from the NIST time string */
int month;
int day;
int year;
int hour;
int minute;
int second;
int US_time; /* the reference to Daylight Savings Time (DST) in the NIST time string */
int US_standard_time; /* Indicates if the United States are observing DST */
int leap_second;
int server_health_digit;
char ms_advanced_str[BUFSIZ];
char nist_str[BUFSIZ];
char otm_str[BUFSIZ]; /* the On-Time Marker (OTM) */
struct tm time_structure;
time_t time_in_seconds;

/**
Initialize the input "time" structures.
Fill them with zeroes.
**/
   memset( tv_ptr, 0, sizeof( *tv_ptr ) );

   memset( tz_ptr, 0, sizeof( *tz_ptr ) );

/* Initialize the client socket logic. */
   rv = lc_client( nist_time_host, "daytime", "tcp", &sd );

/* An error? */
   if ( rv ) return 1;

/**
Read the time string from the NIST server.
rv = The number of bytes read.
**/
   rv = lc_read_data( sd, buf, sizeof( buf ) );

/* Disconnect the socket connection with the NIST time server. */
   close( sd );

/* Null terminate the received NIST time string. */
   buf[rv] = NULL_CHAR;

/* Scan the NIST time string for the necessary values. */
   rv = sscanf( buf,
                "%ld " /* Modified Julian date */
                "%d-%d-%d " /* the date yy-mm-dd */
                "%d:%d:%d " /* the time hh:mm:ss */
                "%d "
                "%d "
                "%d "
                  "%s "
                "%s "
                "%s ",
                &modified_julian_day,
                &year, &month, &day, 
&hour,          &minute, &second,
                &US_time,
                &leap_second,
                &server_health_digit,
                ms_advanced_str,
                nist_str,
                otm_str );

/* Were all 13 time relative fields in the string from the NIST time server? */
   if ( rv != 13 )
   {
      g_error = INCOMPLETE_DATA;
      sprintf( g_error_msg, "The received data buffer was incomplete." );
      return 1;
   }

/* Was the time server healthy? */
   if ( server_health_digit != 0 )
   {
      g_error = NOT_HEALTHY;
      sprintf( g_error_msg, "Server Health Digit: %d", server_health_digit );
      return 1;
   }

/* Set the United States DST indicator flag variable. */
   US_standard_time = ( ( US_time == 0 ) || ( US_time > 50 ) );

   memset( &time_structure, 0, sizeof( time_structure ) );

   time_structure.tm_hour = hour;

   time_structure.tm_min = minute;

   time_structure.tm_sec = second;

   time_structure.tm_mon = month - 1; /* Jan = 0 ... and Dec = 11 */

   time_structure.tm_mday = day;

   time_structure.tm_year = year + 100; /* years since 1900 */

/* Convert the time structure into "time in seconds". */
   time_in_seconds = mktime( &time_structure );

   tv_ptr->tv_sec = time_in_seconds;

   tv_ptr->tv_usec = 0; /* no microseconds */

/* Adjustment relative to GMT. */
   tv_ptr->tv_sec += (-SPM * minutes_west);

/* Handle Daylight Savings Time here. */
   if ( ( use_dst ) && ( ! US_standard_time ) )
   {

/**
Add one hour for DST.
"Spring Forward"
**/
      tv_ptr->tv_sec += SPH;

   }

   return 0;
} /* DayTimeProtocol() */


int lc_client( char *the_host, char *the_service,
          char *the_protocol, int *sd_ptr )
{
struct hostent *hp;
struct servent *sp;
int socket_type;
int rv;

/* Some initializations. */
   g_error = 0;

   *g_error_msg = NULL_CHAR;

/* Get the host information. */
   rv = lc_get_host_info( the_host, &hp );

   if ( rv )
   {
      sprintf( g_error_msg, "gethostbyname() returned NULL for host: %s",
        the_host );
      g_error = NO_HOST_INFO;
      return 1;
   }

/* Get the service information. */
   rv = lc_get_service_info( the_service, the_protocol, &sp );

   if ( rv )
   {
      sprintf( g_error_msg,
            "getservbyname() returned NULL for %s/%s",
               the_service, the_protocol );
      g_error = NO_SERVICE_INFO;
      return 1;
   }

/* Determine the socket type. */
   if ( strcmp( the_protocol, "tcp" ) == 0 )
      socket_type = SOCK_STREAM;
   else socket_type = SOCK_DGRAM;

/* Get a socket. */
   rv = lc_socket( sd_ptr, socket_type );

   if ( rv ) return 1;

/* Attempt the connection. */
   if ( socket_type == SOCK_STREAM )
   {

      rv = lc_connect( *sd_ptr, hp, sp );

      if ( rv != 0 )
      {
         close( *sd_ptr );
         return 1;
      }

   }

   return 0;
} /* lc_client() */


int lc_connect( int sd, struct hostent *hp, struct servent *sp )
{
int rv;
struct sockaddr_in sin;

   memset( &sin, 0, sizeof( sin ) );

   sin.sin_family = AF_INET;

   sin.sin_port = htons( sp->s_port );

   memcpy( &sin.sin_addr.s_addr, hp->h_addr, hp->h_length );

   rv = connect( sd, ADDR_CAST &sin, sizeof( sin ) );

   if ( rv )
   {
      sprintf( g_error_msg, "connect() failed: %s\n", strerror( errno ) );
sprintf(g_error_msg + strlen(g_error_msg),"  sd: %d\n",sd );
      g_error = NO_CONNECT;
   }

   return rv;
} /* lc_connect() */


int lc_get_host_info( char *host_name, struct hostent **hpp )
{
struct hostent *hp;
int rv = 0;

   hp = gethostbyname( host_name );

   if ( hp == (struct hostent *) NULL )
      rv = 1;
   else *hpp = hp;

   return rv;
} /* lc_get_host_info() */


int lc_get_service_info( char *service, char *protocol, struct servent **spp )
{
static struct servent ses; /* service entry structure (ses) */
struct servent *sp;
int rv = 0;

#ifdef use_getservbyname
   sp = getservbyname( service, protocol );

   if ( sp == (struct servent *) NULL )
      rv = 1;
   else *spp = sp;

#else

   ses.s_proto = strdup( "tcp" );

   ses.s_port = 13;

   *spp = &ses;

#endif

   return rv;
} /* lc_get_service_info() */


int lc_socket( int *sd_ptr, int socket_type )
{
int sd;
int rv;

   sd = socket( AF_INET, socket_type, 0 );

   if ( sd == -1 )
   {
      sprintf( g_error_msg, "socket() returned -1" );
      g_error = NO_SOCKET;
      rv = 1;
   }
   else
   {
      *sd_ptr = sd;
      rv = 0;
   }

   return rv;
} /* lc_socket() */


int lc_read_data( int sd, void *data, int max_bytes )
{
int bytes = 0;
int rv;
char c;
char *buf = data;

   while ( ( rv = read( sd, &c, sizeof( c ) ) ) == sizeof( c ) )
   {
      buf[bytes] = c;
      ++bytes;
      if ( bytes == max_bytes ) break;
   }

   return bytes;
} /* lc_read_data() */


