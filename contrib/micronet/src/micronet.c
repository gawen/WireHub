#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main_server(int argc, char* argv[]);
int main_client(int argc, char* argv[]);
int main_read(int argc, char* argv[]);

static int help(char* arg0) {
    fprintf(stderr,
        "\n"
        "Usage: %s COMMAND\n"
        "\n"
        "Commands:\n"
        "  client         Run a client\n"
        "  read           Read configuration\n"
        "  server         Run a server\n"
        "\n",
        arg0
    );

    return EXIT_FAILURE;
}

int main(int argc, char* argv[]) {
    if (argc == 0) {
        return EXIT_FAILURE;
    }

    char* arg0 = argv[0];

    int cmd_idx = 0;
    char* m = strstr(arg0, "micronet");
    if (m != NULL) {
        ++cmd_idx;
    }

    if (argc <= cmd_idx) {
        return help(arg0);
    }

    argc -= cmd_idx;
    argv += cmd_idx;

    if (strcmp(argv[0], "client") == 0) {
        return main_client(argc, argv);
    } else if (strcmp(argv[0], "server") == 0) {
        return main_server(argc, argv);
    } else if (strcmp(argv[0], "read") == 0) {
        return main_read(argc, argv);
    } else {
        return help(arg0);
    }
}
