/* DS1302.pt function prototypes */
void Setup_1302_Port(void);
unsigned char Read_1302_Port(void);
void Set_Time(unsigned char * TimeBuffer);
unsigned int Get_Time(unsigned char * TimeBuffer);
unsigned int Read_1302_Data(unsigned char * TimeBuffer);
void Write_1302_Data(unsigned char * TimeBuffer);
void Enable_1302(void);
void Idle_1302(void);
void Lock_1302 (void);
void DS1302(unsigned char ds1302_bit,unsigned int logical_value);


//port pin data values
//Clock connected to PP0
#define CLK_1302 1
//Reset* I/O connected to PP1
#define RST_1302 2
//Data I/O connected to PP2
#define DAT_1302 4

#define LOW 0
#define HIGH 1
#define READ_CMD    0xbf	/* clock burst read */
#define WRITE_CMD   0xbe	/* clock burst write */

typedef struct {
	unsigned char year;			//00=2000
	unsigned char month;
	unsigned char date;
	unsigned char hour;
	unsigned char min;
	unsigned char dayOfWeek;	//sun=1
   unsigned char sec;
	}TIME_STRUCT;

#define WEEKDAY 	1
#define DATE		2
#define TIME		4
#define AMPM		8
#define PACKED		16
#define MILITARY 	32
#define SECONDS	64

