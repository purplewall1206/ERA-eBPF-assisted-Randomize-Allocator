# randomize layout

total: 67
sum: 超过5万 (55394 from `select DISTINCT(name) FROM ast_struct`)




| struct name               | file                                                                                                                   |
|---------------------------|------------------------------------------------------------------------------------------------------------------------|
| cpuinfo_x86               | [arch/x86/include/asm/processor.h](https://elixir.bootlin.com/linux/v5.15/source/arch/x86/include/asm/processor.h#L145) |
| fscrypt_master_key_secret | [fs/crypto/fscrypt_private.h](https://elixir.bootlin.com/linux/v5.15/source/fs/crypto/fscrypt_private.h#L422)          |
| fscrypt_master_key        | [fs/crypto/fscrypt_private.h](https://elixir.bootlin.com/linux/v5.15/source/fs/crypto/fscrypt_private.h#L497)          |
| mnt_namespace             | [fs/mount.h](https://elixir.bootlin.com/linux/v5.15/source/fs/mount.h#L25)                                             |
| mountpoint                | [fs/mount.h](https://elixir.bootlin.com/linux/v5.15/source/fs/mount.h#L25)                                             |
| nameidata                 | [fs/namei.c](https://elixir.bootlin.com/linux/v5.15/source/fs/namei.c#L585)                                            |
| proc_dir_entry            | [fs/proc/internal.h](https://elixir.bootlin.com/linux/v5.15/source/fs/proc/internal.h#L67)                             |
| proc_inode                | https://elixir.bootlin.com/linux/v5.15/source/fs/proc/internal.h#L103                                                  |
| pde_opener                | https://elixir.bootlin.com/linux/v5.15/source/fs/proc/internal.h#L215                                                  |
| proc_maps_private         | https://elixir.bootlin.com/linux/v5.15/source/fs/proc/internal.h#L298                                                  |
| request_key_auth          | https://elixir.bootlin.com/linux/v5.15/source/include/keys/request_key_auth-type.h#L25                                 |
| linux_binprm              | https://elixir.bootlin.com/linux/v5.15/source/include/linux/binfmts.h#L67                                              |
| linux_binfmt              | https://elixir.bootlin.com/linux/v5.15/source/include/linux/binfmts.h#L103                                             |
| block_device              | https://elixir.bootlin.com/linux/v5.15/source/include/linux/blk_types.h#L52                                            |
| cdev                      | https://elixir.bootlin.com/linux/v5.15/source/include/linux/cdev.h#L21                                                 |
| group_info                | https://elixir.bootlin.com/linux/v5.15/source/include/linux/cred.h#L29                                                 |
| cred                      | https://elixir.bootlin.com/linux/v5.15/source/include/linux/cred.h#L153                                                |
| dentry                    | https://elixir.bootlin.com/linux/v5.15/source/include/linux/dcache.h#L123                                              |
| address_space             | https://elixir.bootlin.com/linux/v5.15/source/include/linux/fs.h                                                       |
| inode                     | https://elixir.bootlin.com/linux/v5.15/source/include/linux/fs.h                                                       |
| file                      |                                                                                                                        |
| file_lock                 |                                                                                                                        |
| super_block               |                                                                                                                        |
| renamedata                |                                                                                                                        |
| file_operations           |                                                                                                                        |
| kiocb                     |                                                                                                                        |
| fs_struct                 | https://elixir.bootlin.com/linux/v5.15/source/include/linux/fs_struct.h#L16                                            |
| kern_ipc_perm             | https://elixir.bootlin.com/linux/v5.15/source/include/linux/ipc.h#L29                                                  |
| ipc_namespace             | https://elixir.bootlin.com/linux/v5.15/source/include/linux/ipc_namespace.h#L73                                        |
| key_preparsed_payload     | https://elixir.bootlin.com/linux/v5.15/source/include/linux/key-type.h#L39                                             |
| key_type                  | https://elixir.bootlin.com/linux/v5.15/source/include/linux/key-type.h#L162                                            |
| kset                      | https://elixir.bootlin.com/linux/v5.15/source/include/linux/kobject.h#L197                                             |
| security_hook_heads       | https://elixir.bootlin.com/linux/v5.15/source/include/linux/lsm_hooks.h#L1571                                          |
| security_hook_list        |                                                                                                                        |
| vm_area_struct            | https://elixir.bootlin.com/linux/v5.15/source/include/linux/mm_types.h#L388                                            |
| mm_struct                 |                                                                                                                        |
| module_kobject            | https://elixir.bootlin.com/linux/v5.15/source/include/linux/module.h#L51                                               |
| module                    |                                                                                                                        |
| vfsmount                  |                                                                                                                        |
| path                      | https://elixir.bootlin.com/linux/v5.15/source/include/linux/path.h#L11                                                 |
| pid_namespace             | https://elixir.bootlin.com/linux/v5.15/source/include/linux/pid_namespace.h#L34                                        |
| proc_ops                  | https://elixir.bootlin.com/linux/v5.15/source/include/linux/proc_fs.h#L45                                              |
| proc_ns_operations        | https://elixir.bootlin.com/linux/v5.15/source/include/linux/proc_ns.h#L25                                              |
| sched_rt_entity           | https://elixir.bootlin.com/linux/v5.15/source/include/linux/sched.h#L581                                               |
| task_struct               |                                                                                                                        |
| signal_struct             | https://elixir.bootlin.com/linux/v5.15/source/include/linux/sched/signal.h#L238                                        |
| ctl_table                 | https://elixir.bootlin.com/linux/v5.15/source/include/linux/sysctl.h#L126                                              |
| time_namespace            | https://elixir.bootlin.com/linux/v5.15/source/include/linux/time_namespace.h#L27                                       |
| tty_struct                | https://elixir.bootlin.com/linux/v5.15/source/include/linux/tty.h#L205                                                 |
| tty_operations            | https://elixir.bootlin.com/linux/v5.15/source/include/linux/tty_driver.h#L292                                          |
| tty_driver                | https://elixir.bootlin.com/linux/v5.15/source/include/linux/tty_driver.h#L326                                          |
| subprocess_info           | https://elixir.bootlin.com/linux/v5.15/source/include/linux/umh.h#L30                                                  |
| user_namespace            | https://elixir.bootlin.com/linux/v5.15/source/include/linux/user_namespace.h#L102                                      |
| uts_namespace             | https://elixir.bootlin.com/linux/v5.15/source/include/linux/utsname.h#L28                                              |
| unix_address              | https://elixir.bootlin.com/linux/v5.15/source/include/net/af_unix.h#L42                                                |
| neighbour                 | https://elixir.bootlin.com/linux/v5.15/source/include/net/neighbour.h#L161                                             |
| net                       | https://elixir.bootlin.com/linux/v5.15/source/include/net/net_namespace.h#L179                                         |
| proto                     | https://elixir.bootlin.com/linux/v5.15/source/include/net/sock.h#L1261                                                 |
| msg_queue                 | https://elixir.bootlin.com/linux/v5.15/source/ipc/msg.c#L62                                                            |
| sem_array                 | https://elixir.bootlin.com/linux/v5.15/source/ipc/sem.c#L127                                                           |
| shmid_kernel              | https://elixir.bootlin.com/linux/v5.15/source/ipc/shm.c#L68                                                            |
| futex_pi_state            | https://elixir.bootlin.com/linux/v5.15/source/kernel/futex.c#L188                                                      |
| futex_q                   | https://elixir.bootlin.com/linux/v5.15/source/kernel/futex.c#L228                                                      |
| task_security_struct      | https://elixir.bootlin.com/linux/v5.15/source/security/selinux/include/objsec.h#L38                                    |
| selinux_state             | https://elixir.bootlin.com/linux/v5.15/source/security/selinux/include/security.h#L107                                 |
| policydb                  | https://elixir.bootlin.com/linux/v5.15/source/security/selinux/ss/policydb.h#L316                                      |
| selinux_policy            | https://elixir.bootlin.com/linux/v5.15/source/security/selinux/ss/services.h#L30                                       |
|                           |                                                                                                                        |