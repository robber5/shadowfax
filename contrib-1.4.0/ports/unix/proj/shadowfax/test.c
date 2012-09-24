#include <getopt.h>
#include <stdio.h>

int main()
{

    int argc = 3;
    char * argv[4] = {0};
    int ch;
    char buf1[255], buf2[255], buf3[25];


    argv[0] = "shit";
    argv[1] = "-b";
    argv[2] = "22";
    argv[3] = 0;

    while( (ch = getopt(argc, argv, "b:")) != -1) {
    	printf("ch = %c\n", ch);   
    }
}
