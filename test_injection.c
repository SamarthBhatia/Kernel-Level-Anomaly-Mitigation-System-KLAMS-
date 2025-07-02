#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>

int main(){
    printf("Simulating Process Injection Attack..........");
    
    pid_t target_pid = fork(); // Find a target process
    if (target_pid == 0){
        // Child process so let it sleep
        printf("Target process (PID: %d) sleeping...\n",getpid());
        sleep(60);
        exit(0);
    }
    sleep(1); //let child start

    // Simulate injection via process_vm_writevs
    struct iovec local_iov; // System calls use arrays of this structure, where each element of the array represents a memory
    //    region, and the whole array represents a vector of memory regions.
    //    The maximum number of iovec structures in that array is limited by
    //    IOV_MAX
    struct iovec remote_iov;
    // iovec - Vector I/O data structure
    // struct iovec {
     //      void   *iov_base;  /* Starting address */
     //      size_t  iov_len;   /* Size of the memory pointed to by iov_base. */
     //  };
    
    char payload[] = "MALICIOUS_PAYLOAD"; // The malicious data we want to inject (like digital poison)

    local_iov.iov_base = payload;
    local_iov.iov_len = strlen(payload);

    printf("Attempting process injection into PID %d...\n", target_pid);

    ssize_t bytes = process_vm_writev(target_pid, &local_iov, 1, &remote_iov, 1, 0);

    if (bytes > 0){
        printf(" Injection successful (%zd bytes written)\n", bytes);
        // Now try to make a network connection, shoudl be blocked 
        printf("Attempting network connection...\n");
        system("curl -s http://example.com || echo 'Connection blocked!'");
    } else{
        printf("Injection failed, damn it");
    }
    return 0;
}