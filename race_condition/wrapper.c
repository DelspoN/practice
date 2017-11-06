#include <unistd.h>

int main()
{
	if (geteuid()!=0) exit(1);
	setuid(geteuid());
	char *args[] = { "/bin/sh", 0 };
	return execve(args[0], args, 0);
}
