// related headers
#include "DhcpLease.hh"

// c sys headers

// cpp stdlib headers
#include <string>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    std::string to_string(DhcpLeaseState state)
    {

        switch (state)
        {
            case DhcpLeaseState::Offered: return "offered";
            case DhcpLeaseState::Bound: return "bound";
            case DhcpLeaseState::Released: return "released";
            case DhcpLeaseState::Expired: return "expired";
        }
        return "offered";

    }

}
