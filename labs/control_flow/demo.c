#define _POSIX_C_SOURCE 200809L
#include <stddef.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define INPUT_CAPACITY 32

struct demo_state {
    char input[INPUT_CAPACITY];
    void (*callback)(void);
};

static void normal_message(void);
static void hello_world(void);

static struct demo_state state = { .callback = normal_message };

static void normal_message(void)
{
    puts("Normal callback reached.");
}

static void hello_world(void)
{
    puts("HELLO WORLD: benign callback reached.");
}

static int print_demo_info(void)
{
    printf("TARGET_ADDR=0x%" PRIxPTR "\n", (uintptr_t)hello_world);
    printf("CALLBACK_OFFSET=%zu\n", offsetof(struct demo_state, callback));
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--demo-info") == 0)
        return print_demo_info();

#ifdef PATCHED_BUILD
    char staging[INPUT_CAPACITY + sizeof(state.callback) + 1];
    ssize_t received = read(STDIN_FILENO, staging, sizeof(staging));
    if (received < 0) {
        perror("read");
        return 1;
    }
    if ((size_t)received > sizeof(state.input)) {
        puts("Patched build rejected oversized input.");
        return 0;
    }
    memcpy(state.input, staging, (size_t)received);
#else
    /* Teaching bug: reads past input[] and can overwrite callback. */
    ssize_t received = read(STDIN_FILENO, state.input,
                            sizeof(state.input) + sizeof(state.callback));
    if (received < 0) {
        perror("read");
        return 1;
    }
#endif

    printf("Accepted %zd input bytes; dispatching callback.\n", received);
    state.callback();
    return 0;
}
