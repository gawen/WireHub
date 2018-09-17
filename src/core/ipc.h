#ifndef WIREHUB_IPC_H
#define WIREHUB_IPC_H

int ipc_prepare(void);
int ipc_bind(const char* interface, int force);
int ipc_connect(const char* interface);
int ipc_accept(int sock);
int ipc_unlink(const char* interface);
int ipc_list(int(*cb)(const char*, void*), void* ud);

#endif  // WIREHUB_IPC_H

