#ifndef NODE_MONITOR_METRIC_HH
#define NODE_MONITOR_METRIC_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <string>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // a single telemetry sample received from a simulated device
    struct Metric
    {

        std::string m_hostname { }; // identifier of the device that emitted the sample
        std::string m_vendor { }; // vendor of the device (cisco, juniper, paloalto, etc.)
        std::chrono::system_clock::time_point m_timestamp { }; // wall clock time when the sample was received
        std::string m_payload { }; // raw json payload as received from the device
        double m_cpu { 0.0 }; // cpu usage percentage parsed from the payload
        double m_memory { 0.0 }; // memory usage percentage parsed from the payload

    };

}

#endif // NODE_MONITOR_METRIC_HH
