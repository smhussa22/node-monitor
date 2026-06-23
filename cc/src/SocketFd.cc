// related headers
#include "SocketFd.hh"

// c sys headers

// cpp stdlib headers

// 3rd party headers

// project headers

namespace NodeMonitor
{

    SocketFd::SocketFd(int fd)
    {

    }

    SocketFd::~SocketFd()
    {

    }

    SocketFd::SocketFd(SocketFd&& other) noexcept
    {

    }

    SocketFd& SocketFd::operator=(SocketFd&& other) noexcept
    {

        return *this;

    }

    int SocketFd::get() const noexcept
    {

        return -1;

    }

    int SocketFd::release() noexcept
    {

        return -1;

    }

    void SocketFd::reset(int fd) noexcept
    {

    }

    bool SocketFd::is_valid() const noexcept
    {

        return false;

    }

}
