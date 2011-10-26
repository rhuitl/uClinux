typedef struct {
	unsigned char *ptr;
	int width;
	int height;
	int length;
	int line_length;
	int inverted;
} Bitmap;

typedef struct {
	Bitmap bm;
	short *of;
	int w;
	int h;
	int nc;
} Font;

void display_1(void);
void display_2(void);

extern Bitmap screen;
