#include<stdio.h>
#include<stdlib.h>

int main(){
    if(!fork()){
        system("./debug.sh");
        sleep(10);
        exit(0);

    }
    system("./panda.sh");
}
