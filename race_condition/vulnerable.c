#include <unistd.h>
int main(int argc, char **argv, char **envp)
{
	char buf[4096];

	if (argc < 2)
	{
		if (readlink("/proc/self/exe", buf, sizeof(buf)) < 0) return 1;
		char *args[] = { buf, "1", 0 };
		if (execve(args[0], args, 0) < 0) return 1;
	}

	return 0;
}
