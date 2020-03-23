#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char input[13];
	char *password = "flag{gotcha}";
	printf("Enter flag to validate: ");
	fgets(input, sizeof(input), stdin);
	if(strncmp(input, password, 12) == 0)
	{
		printf("Correct, you may now proceed.\n");
	}
	else
	{
		printf("Not the valid flag.\n");
	}
	return 0;
}