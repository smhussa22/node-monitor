#ifndef NODE_MONITOR_SOCKET_FD_HH
#define NODE_MONITOR_SOCKET_FD_HH

// related headers

// c sys headers

// cpp stdlib headers

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // raii wrapper that owns a posix socket file descriptor and closes it on destruction
    class SocketFd
    {

    public:

        SocketFd() = default;
        explicit SocketFd(int fd);
        ~SocketFd();

        SocketFd(const SocketFd&) = delete;
        SocketFd& operator=(const SocketFd&) = delete;

        SocketFd(SocketFd&& other) noexcept;
        SocketFd& operator=(SocketFd&& other) noexcept;

        // accessor for the underlying raw fd; returns -1 when none is owned
        int get() const noexcept;

        // release ownership of the fd and return it to the caller without closing it
        int release() noexcept;

        // close the currently owned fd if any, and take ownership of the new fd
        void reset(int fd = -1) noexcept;

        // true when an fd is currently owned
        bool is_valid() const noexcept;

    private:

        int m_fd { -1 }; // owned posix socket fd, or -1 when no fd is owned

    };

}

#endif // NODE_MONITOR_SOCKET_FD_HH
