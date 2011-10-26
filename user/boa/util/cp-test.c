#include <stdio.h>
#include <unistd.h>

void main()
{
	int x;
	
	printf("Content-type: text/html\n");
	printf("\n");
	printf("<html><head><title>Codepage conversion testing page</title></head>"
				 "<center><h1>Codepage %s</h1></center>"
			   "<body><table><tr><td>&nbsp;<td>0<td>1<td>2<td>3<td>4<td>5<td>6<td>7<td>8"
				 "<td>9<td>A<td>B<td>C<td>D<td>E<td>F",
				 getenv("CLIENT_CODEPAGE"));
	for (x=0;x<0x100;x++)
	{
		if ((x%0x10) == 0)
			printf("<tr><td>%X",x/0x10);
		printf("<td>");
		switch (x)
		{
			case '\n': printf("&nbsp;");break;
			case ' ': printf("&nbsp;");break;
			case '<': printf("&lt;");break;
			case '>': printf("&gt;");break;
			default: printf("%c",x);break;
		}
	}
	printf("</table></body></html>");
}
