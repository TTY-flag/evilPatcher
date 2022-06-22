gcc -o hello32_nopie -no-pie -m32 hello.c
gcc -o hello32_pie -pie -m32 hello.c
gcc -o hello64_nopie -no-pie hello.c
gcc -o hello64_pie -pie -fPIC hello.c
