#ifndef BACKENDS_TRAFFIC_ANALYSIS_TRAFFIC_DIGEST_H_
#define BACKENDS_TRAFFIC_ANALYSIS_TRAFFIC_DIGEST_H_

#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
#include <map>

namespace P4 {

struct TrafficRecord {
    uint64_t timestamp;
    int pktLen;
    std::string srcIP;
    std::string dstIP;
    int srcPort;
    int dstPort;
    int protocol;
};

class TrafficParseException : public std::runtime_error {
public:
    explicit TrafficParseException(const std::string& message)
        : std::runtime_error(message) {}
};

/**
 * Parses a traffic trace file.
 *
 * The expected format per line is:
 * timestamp pkt_len srcIP_int dstIP_int srcPort dstPort proto [ignored_flowid]
 * where IPs are expected as integer strings.
 *
 * @param filename The path to the traffic trace file.
 * @return A vector of TrafficRecord structs.
 * @throws TrafficParseException if the file cannot be opened or a line is malformed.
 */
std::vector<TrafficRecord> parseTrafficTrace(const std::string &filename);

// Type alias for control plane rules (e.g., srcIP -> dip)
using ControlPlaneRules = std::map<std::string, std::string>;

/**
 * Parses a control plane rules file.
 *
 * Expected format: src_ip_key assigned_dip_value per line.
 *
 * @param filename The path to the rules file.
 * @return A map representing the parsed rules.
 * @throws TrafficParseException if the file cannot be opened or a line is malformed.
 */
ControlPlaneRules parseControlPlaneRules(const std::string &filename);

// Forward declare StateBlock to avoid circular dependency if needed later
// class StateBlock;

} // namespace P4

#endif /* BACKENDS_TRAFFIC_ANALYSIS_TRAFFIC_DIGEST_H_ */ 