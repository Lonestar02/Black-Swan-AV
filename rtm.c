#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <errno.h>
#include <sys/wait.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + NAME_MAX + 1))

void CallDetectionEngine(const char* filePath) {
    printf("[+] Called detection for: %s\n", filePath);
    fflush(stdout);

    pid_t pid = fork();
    if (pid == 0) {  // child process
        execl("/home/moon/antivirusProject/engine", "./engine", filePath, (char *)NULL);
        perror("execl failed");
        exit(1);
    } else if (pid < 0) {
        perror("fork failed");
    } else {
        wait(NULL);  // parent waits for child
    }
}

void* MonitorDirectoryThread(void* arg) {
    char* directoryPath = (char*)arg;

    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        free(directoryPath);
        return NULL;
    }

    int wd = inotify_add_watch(fd, directoryPath, IN_CREATE | IN_MODIFY);
    if (wd < 0) {
        fprintf(stderr, "[-] Failed to add watch on directory: %s -> %s\n", directoryPath, strerror(errno));
        close(fd);
        free(directoryPath);
        return NULL;
    }

    printf("[+] Monitoring directory: %s\n", directoryPath);
    fflush(stdout);

    char buffer[BUF_LEN];
    while (1) {
        ssize_t length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }

        ssize_t i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len) {
                char fullPath[PATH_MAX];
                snprintf(fullPath, sizeof(fullPath), "%s/%s", directoryPath, event->name);
                printf("[+] Change detected in file: %s\n", fullPath);
                fflush(stdout);
                CallDetectionEngine(fullPath);
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    free(directoryPath);
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <directory1> [directory2] [...]\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        pthread_t thread_id;
        char* dir = strdup(argv[i]);
        if (pthread_create(&thread_id, NULL, MonitorDirectoryThread, dir) != 0) {
            fprintf(stderr, "[-] Failed to create thread for: %s\n", argv[i]);
            free(dir);
        }
        pthread_detach(thread_id);
    }

    printf("Press 'q' followed by Enter to exit...\n");
    char userInput;
    do {
        userInput = getchar();
    } while (userInput != 'q');

    return 0;
}
