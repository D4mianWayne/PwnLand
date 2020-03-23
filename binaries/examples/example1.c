#include <stdio.h>
#include <string.h>
int main()
{
	char *input;
	char *password = "flag{gotcha}";
	fgets(input, 12, stdin);
	if( !strcmp(input, password))
	{
		printf("%s is not the valid flag.\n", input);
	}
	printf("Correct, you may now proceed.\n");
	return 0;
}