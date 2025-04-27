#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Syscall {
    /// read()
    Read = 0,
    /// write()
    Write = 1,
    /// open()
    Open = 2,
    /// close()
    Close = 3,
    /// stat()
    Stat = 4,
    /// fstat()
    Fstat = 5,
    /// lstat()
    Lstat = 6,
    /// poll()
    Poll = 7,
    /// lseek()
    Lseek = 8,
    /// mmap()
    Mmap = 9,
    /// mprotect()
    Mprotect = 10,
    /// munmap()
    Munmap = 11,
    /// brk()
    Brk = 12,
    /// rt_sigaction()
    RtSigaction = 13,
    /// rt_sigprocmask()
    RtSigprocmask = 14,
    /// rt_sigreturn()
    RtSigreturn = 15,
    /// ioctl()
    Ioctl = 16,
    /// pread64()
    Pread64 = 17,
    /// pwrite64()
    Pwrite64 = 18,
    /// readv()
    Readv = 19,
    /// writev()
    Writev = 20,
    /// access()
    Access = 21,
    /// pipe()
    Pipe = 22,
    /// select()
    Select = 23,
    /// sched_yield()
    SchedYield = 24,
    /// mremap()
    Mremap = 25,
    /// msync()
    Msync = 26,
    /// mincore()
    Mincore = 27,
    /// madvise()
    Madvise = 28,
    /// shmget()
    Shmget = 29,
    /// shmat()
    Shmat = 30,
    /// shmctl()
    Shmctl = 31,
    /// dup()
    Dup = 32,
    /// dup2()
    Dup2 = 33,
    /// pause()
    Pause = 34,
    /// nanosleep()
    Nanosleep = 35,
    /// getitimer()
    Getitimer = 36,
    /// alarm()
    Alarm = 37,
    /// setitimer()
    Setitimer = 38,
    /// getpid()
    Getpid = 39,
    /// sendfile()
    Sendfile = 40,
    /// socket()
    Socket = 41,
    /// connect()
    Connect = 42,
    /// accept()
    Accept = 43,
    /// sendto()
    Sendto = 44,
    /// recvfrom()
    Recvfrom = 45,
    /// sendmsg()
    Sendmsg = 46,
    /// recvmsg()
    Recvmsg = 47,
    /// shutdown()
    Shutdown = 48,
    /// bind()
    Bind = 49,
    /// listen()
    Listen = 50,
    /// getsockname()
    Getsockname = 51,
    /// getpeername()
    Getpeername = 52,
    /// socketpair()
    Socketpair = 53,
    /// setsockopt()
    Setsockopt = 54,
    /// getsockopt()
    Getsockopt = 55,
    /// clone()
    Clone = 56,
    /// fork()
    Fork = 57,
    /// vfork()
    Vfork = 58,
    /// execve()
    Execve = 59,
    /// exit()
    Exit = 60,
    /// wait4()
    Wait4 = 61,
    /// kill()
    Kill = 62,
    /// uname()
    Uname = 63,
    /// semget()
    Semget = 64,
    /// semop()
    Semop = 65,
    /// semctl()
    Semctl = 66,
    /// shmdt()
    Shmdt = 67,
    /// msgget()
    Msgget = 68,
    /// msgsnd()
    Msgsnd = 69,
    /// msgrcv()
    Msgrcv = 70,
    /// msgctl()
    Msgctl = 71,
    /// fcntl()
    Fcntl = 72,
    /// flock()
    Flock = 73,
    /// fsync()
    Fsync = 74,
    /// fdatasync()
    Fdatasync = 75,
    /// truncate()
    Truncate = 76,
    /// ftruncate()
    Ftruncate = 77,
    /// getdents()
    Getdents = 78,
    /// getcwd()
    Getcwd = 79,
    /// chdir()
    Chdir = 80,
    /// fchdir()
    Fchdir = 81,
    /// rename()
    Rename = 82,
    /// mkdir()
    Mkdir = 83,
    /// rmdir()
    Rmdir = 84,
    /// creat()
    Creat = 85,
    /// link()
    Link = 86,
    /// unlink()
    Unlink = 87,
    /// symlink()
    Symlink = 88,
    /// readlink()
    Readlink = 89,
    /// chmod()
    Chmod = 90,
    /// fchmod()
    Fchmod = 91,
    /// chown()
    Chown = 92,
    /// fchown()
    Fchown = 93,
    /// lchown()
    Lchown = 94,
    /// umask()
    Umask = 95,
    /// gettimeofday()
    Gettimeofday = 96,
    /// getrlimit()
    Getrlimit = 97,
    /// getrusage()
    Getrusage = 98,
    /// sysinfo()
    Sysinfo = 99,
    /// times()
    Times = 100,
    /// ptrace()
    Ptrace = 101,
    /// getuid()
    Getuid = 102,
    /// syslog()
    Syslog = 103,
    /// getgid()
    Getgid = 104,
    /// setuid()
    Setuid = 105,
    /// setgid()
    Setgid = 106,
    /// geteuid()
    Geteuid = 107,
    /// getegid()
    Getegid = 108,
    /// setpgid()
    Setpgid = 109,
    /// getppid()
    Getppid = 110,
    /// getpgrp()
    Getpgrp = 111,
    /// setsid()
    Setsid = 112,
    /// setreuid()
    Setreuid = 113,
    /// setregid()
    Setregid = 114,
    /// getgroups()
    Getgroups = 115,
    /// setgroups()
    Setgroups = 116,
    /// setresuid()
    Setresuid = 117,
    /// getresuid()
    Getresuid = 118,
    /// setresgid()
    Setresgid = 119,
    /// getresgid()
    Getresgid = 120,
    /// getpgid()
    Getpgid = 121,
    /// setfsuid()
    Setfsuid = 122,
    /// setfsgid()
    Setfsgid = 123,
    /// getsid()
    Getsid = 124,
    /// capget()
    Capget = 125,
    /// capset()
    Capset = 126,
    /// rt_sigpending()
    RtSigpending = 127,
    /// rt_sigtimedwait()
    RtSigtimedwait = 128,
    /// rt_sigqueueinfo()
    RtSigqueueinfo = 129,
    /// rt_sigsuspend()
    RtSigsuspend = 130,
    /// sigaltstack()
    Sigaltstack = 131,
    /// utime()
    Utime = 132,
    /// mknod()
    Mknod = 133,
    /// uselib()
    Uselib = 134,
    /// personality()
    Personality = 135,
    /// ustat()
    Ustat = 136,
    /// statfs()
    Statfs = 137,
    /// fstatfs()
    Fstatfs = 138,
    /// sysfs()
    Sysfs = 139,
    /// getpriority()
    Getpriority = 140,
    /// setpriority()
    Setpriority = 141,
    /// sched_setparam()
    SchedSetparam = 142,
    /// sched_getparam()
    SchedGetparam = 143,
    /// sched_setscheduler()
    SchedSetscheduler = 144,
    /// sched_getscheduler()
    SchedGetscheduler = 145,
    /// sched_get_priority_max()
    SchedGetPriorityMax = 146,
    /// sched_get_priority_min()
    SchedGetPriorityMin = 147,
    /// sched_rr_get_interval()
    SchedRrGetInterval = 148,
    /// mlock()
    Mlock = 149,
    /// munlock()
    Munlock = 150,
    /// mlockall()
    Mlockall = 151,
    /// munlockall()
    Munlockall = 152,
    /// vhangup()
    Vhangup = 153,
    /// modify_ldt()
    ModifyLdt = 154,
    /// pivot_root()
    PivotRoot = 155,
    /// _sysctl()
    Sysctl = 156,
    /// prctl()
    Prctl = 157,
    /// arch_prctl()
    ArchPrctl = 158,
    /// adjtimex()
    Adjtimex = 159,
    /// setrlimit()
    Setrlimit = 160,
    /// chroot()
    Chroot = 161,
    /// sync()
    Sync = 162,
    /// acct()
    Acct = 163,
    /// settimeofday()
    Settimeofday = 164,
    /// mount()
    Mount = 165,
    /// umount2()
    Umount2 = 166,
    /// swapon()
    Swapon = 167,
    /// swapoff()
    Swapoff = 168,
    /// reboot()
    Reboot = 169,
    /// sethostname()
    Sethostname = 170,
    /// setdomainname()
    Setdomainname = 171,
    /// iopl()
    Iopl = 172,
    /// ioperm()
    Ioperm = 173,
    /// create_module()
    CreateModule = 174,
    /// init_module()
    InitModule = 175,
    /// delete_module()
    DeleteModule = 176,
    /// get_kernel_syms()
    GetKernelSyms = 177,
    /// query_module()
    QueryModule = 178,
    /// quotactl()
    Quotactl = 179,
    /// nfsservctl()
    Nfsservctl = 180,
    /// getpmsg()
    Getpmsg = 181,
    /// putpmsg()
    Putpmsg = 182,
    /// afs_syscall()
    AfsSyscall = 183,
    /// tuxcall()
    Tuxcall = 184,
    /// security()
    Security = 185,
    /// gettid()
    Gettid = 186,
    /// readahead()
    Readahead = 187,
    /// setxattr()
    Setxattr = 188,
    /// lsetxattr()
    Lsetxattr = 189,
    /// fsetxattr()
    Fsetxattr = 190,
    /// getxattr()
    Getxattr = 191,
    /// lgetxattr()
    Lgetxattr = 192,
    /// fgetxattr()
    Fgetxattr = 193,
    /// listxattr()
    Listxattr = 194,
    /// llistxattr()
    Llistxattr = 195,
    /// flistxattr()
    Flistxattr = 196,
    /// removexattr()
    Removexattr = 197,
    /// lremovexattr()
    Lremovexattr = 198,
    /// fremovexattr()
    Fremovexattr = 199,
    /// tkill()
    Tkill = 200,
    /// time()
    Time = 201,
    /// futex()
    Futex = 202,
    /// sched_setaffinity()
    SchedSetaffinity = 203,
    /// sched_getaffinity()
    SchedGetaffinity = 204,
    /// set_thread_area()
    SetThreadArea = 205,
    /// io_setup()
    IoSetup = 206,
    /// io_destroy()
    IoDestroy = 207,
    /// io_getevents()
    IoGetevents = 208,
    /// io_submit()
    IoSubmit = 209,
    /// io_cancel()
    IoCancel = 210,
    /// get_thread_area()
    GetThreadArea = 211,
    /// lookup_dcookie()
    LookupDcookie = 212,
    /// epoll_create()
    EpollCreate = 213,
    /// epoll_ctl_old()
    EpollCtlOld = 214,
    /// epoll_wait_old()
    EpollWaitOld = 215,
    /// remap_file_pages()
    RemapFilePages = 216,
    /// getdents64()
    Getdents64 = 217,
    /// set_tid_address()
    SetTidAddress = 218,
    /// restart_syscall()
    RestartSyscall = 219,
    /// semtimedop()
    Semtimedop = 220,
    /// fadvise64()
    Fadvise64 = 221,
    /// timer_create()
    TimerCreate = 222,
    /// timer_settime()
    TimerSettime = 223,
    /// timer_gettime()
    TimerGettime = 224,
    /// timer_getoverrun()
    TimerGetoverrun = 225,
    /// timer_delete()
    TimerDelete = 226,
    /// clock_settime()
    ClockSettime = 227,
    /// clock_gettime()
    ClockGettime = 228,
    /// clock_getres()
    ClockGetres = 229,
    /// clock_nanosleep()
    ClockNanosleep = 230,
    /// exit_group()
    ExitGroup = 231,
    /// epoll_wait()
    EpollWait = 232,
    /// epoll_ctl()
    EpollCtl = 233,
    /// tgkill()
    Tgkill = 234,
    /// utimes()
    Utimes = 235,
    /// vserver()
    Vserver = 236,
    /// mbind()
    Mbind = 237,
    /// set_mempolicy()
    SetMempolicy = 238,
    /// get_mempolicy()
    GetMempolicy = 239,
    /// mq_open()
    MqOpen = 240,
    /// mq_unlink()
    MqUnlink = 241,
    /// mq_timedsend()
    MqTimedsend = 242,
    /// mq_timedreceive()
    MqTimedreceive = 243,
    /// mq_notify()
    MqNotify = 244,
    /// mq_getsetattr()
    MqGetsetattr = 245,
    /// kexec_load()
    KexecLoad = 246,
    /// waitid()
    Waitid = 247,
    /// add_key()
    AddKey = 248,
    /// request_key()
    RequestKey = 249,
    /// keyctl()
    Keyctl = 250,
    /// ioprio_set()
    IoprioSet = 251,
    /// ioprio_get()
    IoprioGet = 252,
    /// inotify_init()
    InotifyInit = 253,
    /// inotify_add_watch()
    InotifyAddWatch = 254,
    /// inotify_rm_watch()
    InotifyRmWatch = 255,
    /// migrate_pages()
    MigratePages = 256,
    /// openat()
    Openat = 257,
    /// mkdirat()
    Mkdirat = 258,
    /// mknodat()
    Mknodat = 259,
    /// fchownat()
    Fchownat = 260,
    /// futimesat()
    Futimesat = 261,
    /// newfstatat()
    Newfstatat = 262,
    /// unlinkat()
    Unlinkat = 263,
    /// renameat()
    Renameat = 264,
    /// linkat()
    Linkat = 265,
    /// symlinkat()
    Symlinkat = 266,
    /// readlinkat()
    Readlinkat = 267,
    /// fchmodat()
    Fchmodat = 268,
    /// faccessat()
    Faccessat = 269,
    /// pselect6()
    Pselect6 = 270,
    /// ppoll()
    Ppoll = 271,
    /// unshare()
    Unshare = 272,
    /// set_robust_list()
    SetRobustList = 273,
    /// get_robust_list()
    GetRobustList = 274,
    /// splice()
    Splice = 275,
    /// tee()
    Tee = 276,
    /// sync_file_range()
    SyncFileRange = 277,
    /// vmsplice()
    Vmsplice = 278,
    /// move_pages()
    MovePages = 279,
    /// utimensat()
    Utimensat = 280,
    /// epoll_pwait()
    EpollPwait = 281,
    /// signalfd()
    Signalfd = 282,
    /// timerfd_create()
    TimerfdCreate = 283,
    /// eventfd()
    Eventfd = 284,
    /// fallocate()
    Fallocate = 285,
    /// timerfd_settime()
    TimerfdSettime = 286,
    /// timerfd_gettime()
    TimerfdGettime = 287,
    /// accept4()
    Accept4 = 288,
    /// signalfd4()
    Signalfd4 = 289,
    /// eventfd2()
    Eventfd2 = 290,
    /// epoll_create1()
    EpollCreate1 = 291,
    /// dup3()
    Dup3 = 292,
    /// pipe2()
    Pipe2 = 293,
    /// inotify_init1()
    InotifyInit1 = 294,
    /// preadv()
    Preadv = 295,
    /// pwritev()
    Pwritev = 296,
    /// rt_tgsigqueueinfo()
    RtTgsigqueueinfo = 297,
    /// perf_event_open()
    PerfEventOpen = 298,
    /// recvmmsg()
    Recvmmsg = 299,
    /// fanotify_init()
    FanotifyInit = 300,
    /// fanotify_mark()
    FanotifyMark = 301,
    /// prlimit64()
    Prlimit64 = 302,
    /// name_to_handle_at()
    NameToHandleAt = 303,
    /// open_by_handle_at()
    OpenByHandleAt = 304,
    /// clock_adjtime()
    ClockAdjtime = 305,
    /// syncfs()
    Syncfs = 306,
    /// sendmmsg()
    Sendmmsg = 307,
    /// setns()
    Setns = 308,
    /// getcpu()
    Getcpu = 309,
    /// process_vm_readv()
    ProcessVmReadv = 310,
    /// process_vm_writev()
    ProcessVmWritev = 311,
    /// kcmp()
    Kcmp = 312,
    /// finit_module()
    FinitModule = 313,
    /// sched_setattr()
    SchedSetattr = 314,
    /// sched_getattr()
    SchedGetattr = 315,
    /// renameat2()
    Renameat2 = 316,
    /// seccomp()
    Seccomp = 317,
    /// getrandom()
    Getrandom = 318,
    /// memfd_create()
    MemfdCreate = 319,
    /// kexec_file_load()
    KexecFileLoad = 320,
    /// bpf()
    Bpf = 321,
    /// execveat()
    Execveat = 322,
    /// userfaultfd()
    Userfaultfd = 323,
    /// membarrier()
    Membarrier = 324,
    /// mlock2()
    Mlock2 = 325,
    /// copy_file_range()
    CopyFileRange = 326,
    /// preadv2()
    Preadv2 = 327,
    /// pwritev2()
    Pwritev2 = 328,
    /// pkey_mprotect()
    PkeyMprotect = 329,
    /// pkey_alloc()
    PkeyAlloc = 330,
    /// pkey_free()
    PkeyFree = 331,
    /// statx()
    Statx = 332,
    /// io_pgetevents()
    IoPgetevents = 333,
    /// rseq()
    Rseq = 334,
    /// pidfd_send_signal()
    PidfdSendSignal = 424,
    /// io_uring_setup()
    IoUringSetup = 425,
    /// io_uring_enter()
    IoUringEnter = 426,
    /// io_uring_register()
    IoUringRegister = 427,
    /// open_tree()
    OpenTree = 428,
    /// move_mount()
    MoveMount = 429,
    /// fsopen()
    Fsopen = 430,
    /// fsconfig()
    Fsconfig = 431,
    /// fsmount()
    Fsmount = 432,
    /// fspick()
    Fspick = 433,
    /// pidfd_open()
    PidfdOpen = 434,
    /// clone3()
    Clone3 = 435,
}
