// related headers
#include "SocketFd.hh"

// c sys headers
#include <unistd.h>

// cpp stdlib headers

// 3rd party headers

// project headers

namespace NodeMonitor
{

    SocketFd::SocketFd(int fd)
        : m_fd { fd }
    {

    }

    SocketFd::~SocketFd()
    {

        if (m_fd != -1) ::close(m_fd);

    }

    SocketFd::SocketFd(SocketFd&& other) noexcept
        : m_fd { other.release() }
    {

    }

    SocketFd& SocketFd::operator=(SocketFd&& other) noexcept
    {

        if (this != &other) reset(other.release());
        return *this;

    }

    int SocketFd::get() const noexcept
    {

        return m_fd;

    }

    int SocketFd::release() noexcept
    {

        int fd { m_fd };
        m_fd = -1;
        return fd;

    }

    void SocketFd::reset(int fd) noexcept
    {

        if (m_fd != -1) ::close(m_fd);
        m_fd = fd;

    }

    bool SocketFd::is_valid() const noexcept
    {

        return m_fd != -1;

    }

}
