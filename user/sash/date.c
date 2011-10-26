/* date.c bradkemp@indusriver.com */

#include <time.h>
#include <stdio.h>

static const char invalid_date[] = "Invalid date %s\n";
int do_date(int argc, char * argv[])
{

    time_t tm;
    struct tm tm_time;
    time(&tm);
    memcpy(&tm_time, localtime(&tm), sizeof(tm_time));
    
    if (argc > 1) {
	int nr;
        
	nr = sscanf(argv[1], "%2d%2d%2d%2d%d",
                    &(tm_time.tm_mon),
                    &(tm_time.tm_mday),
                    &(tm_time.tm_hour),
                    &(tm_time.tm_min), &(tm_time.tm_year));
        
	if (nr < 4 || nr > 5) {
            fprintf(stderr, invalid_date, argv[1]);
            return(0);
	}
        
	/* correct for century  - minor Y2K problem here? */
	if (tm_time.tm_year >= 1900)
            tm_time.tm_year -= 1900;
	/* adjust date */
	tm_time.tm_mon -= 1;
        
        if((tm = mktime(&tm_time)) < 0) {
            fprintf(stderr, invalid_date, argv[1]);
            return(0);
        }
        
        if(stime(&tm) < 0) {
            fprintf(stderr, "Unable to set date\n");
            return(0);
        }
            
        return (0);
        
    }
    printf("%s\n",asctime(&tm_time));

    return(0);
}



