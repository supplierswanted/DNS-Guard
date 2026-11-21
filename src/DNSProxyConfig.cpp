#include "dnsguard/DNSProxy.hpp"
#include <charconv>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

namespace dnsguard {
namespace {
std::istringstream openBounded(const std::filesystem::path& path, std::size_t limit) {
    std::ifstream file(path,std::ios::binary);
    if (!file) throw std::runtime_error("cannot open configuration file");
    std::string text(limit+1,'\0');
    file.read(text.data(),static_cast<std::streamsize>(text.size()));
    const auto count = static_cast<std::size_t>(file.gcount());
    if (count > limit) throw std::runtime_error("configuration file too large");
    if (!file.eof()) throw std::runtime_error("configuration file read failed");
    text.resize(count);
    return std::istringstream(std::move(text));
}
std::string trim(std::string s) {
    const auto first = s.find_first_not_of(" \t\r");
    return first == s.npos ? "" : s.substr(first, s.find_last_not_of(" \t\r") - first + 1);
}
unsigned number(const std::string& s, unsigned low, unsigned high) {
    unsigned n = 0;
    const auto r = std::from_chars(s.data(), s.data()+s.size(), n);
    if (r.ec != std::errc{} || r.ptr != s.data()+s.size() || n < low || n > high)
        throw std::runtime_error("configuration number outside allowed range");
    return n;
}
void names(const std::filesystem::path& path, std::vector<Name>& out) {
    auto file = openBounded(path, 4*1024*1024);
    std::unordered_set<std::string> seen;
    for (const auto& existing : out)
        seen.insert(std::string(existing.wire.begin(),existing.wire.end()));
    for (std::string line; std::getline(file,line);) {
        line = trim(line.substr(0,line.find('#')));
        if (line.empty()) continue;
        Name name;
        if (line.back() == '.') line.pop_back();
        for (std::size_t pos = 0; pos < line.size();) {
            const auto end = line.find('.',pos);
            const auto label = line.substr(pos,end == line.npos ? end : end-pos);
            if (label.empty() || label.size() > 63) throw std::runtime_error("invalid domain label");
            name.wire.push_back(static_cast<std::uint8_t>(label.size()));
            for (char raw : label) {
                const auto c = static_cast<unsigned char>(raw);
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '_'))
                    throw std::runtime_error("domain lists require ASCII labels (use punycode for IDNs)");
                name.wire.push_back(static_cast<std::uint8_t>(
                    c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c));
            }
            if (end == line.npos) break;
            pos = end+1;
            if (pos == line.size()) throw std::runtime_error("empty domain label");
        }
        name.wire.push_back(0);
        if (!sameName(name,name))
            throw std::runtime_error("domain list size or name limit");
        if (seen.insert(std::string(name.wire.begin(),name.wire.end())).second) {
            if (out.size() >= max_domain_list_entries)
                throw std::runtime_error("domain list size or name limit");
            out.push_back(std::move(name));
        }
    }
    if (!file.eof()) throw std::runtime_error("domain list read failed");
}
}
ProxyConfig loadProxyConfig(const std::filesystem::path& path) {
    auto file = openBounded(path, 65536);
    ProxyConfig config;
    config.config_path = std::filesystem::absolute(path);
    config.lists.enabled = true;
    config.lists.include_subdomains = true;
    std::set<std::string> keys;
    for (std::string line; std::getline(file,line);) {
        line = trim(line.substr(0,line.find('#')));
        if (line.empty()) continue;
        const auto equal = line.find('=');
        if (equal == line.npos) throw std::runtime_error("expected key=value");
        const auto key = trim(line.substr(0,equal)), value = trim(line.substr(equal+1));
        if (!keys.insert(key).second || value.empty()) throw std::runtime_error("duplicate or empty configuration");
        if (key == "listen_ipv4") config.listen_ipv4 = value;
        else if (key == "upstream_ipv4") config.upstream_ipv4 = value;
        else if (key == "listen_port") config.listen_port = static_cast<std::uint16_t>(number(value,1,65535));
        else if (key == "listen_ipv6_port") config.listen_ipv6_port = static_cast<std::uint16_t>(number(value,1,65535));
        else if (key == "upstream_port") config.upstream_port = static_cast<std::uint16_t>(number(value,1,65535));
        else if (key == "secondary_upstream_ipv4") config.secondary_upstream_ipv4 = value;
        else if (key == "secondary_upstream_port") config.secondary_upstream_port = static_cast<std::uint16_t>(number(value,1,65535));
        else if (key == "rebind_protection") config.rebind_protection = number(value,0,1) != 0;
        else if (key == "timeout_ms") config.timeout_ms = number(value,100,10000);
        else if (key == "workers") config.workers = number(value,1,32);
        else if (key == "queue_capacity") config.queue_capacity = number(value,1,256);
        else if (key == "blocklist") {
            config.blocklist_path = std::filesystem::absolute(path.parent_path()/value);
            names(config.blocklist_path,config.lists.denied);
        } else if (key == "feedlist") {
            config.feedlist_path = std::filesystem::absolute(path.parent_path()/value);
            names(config.feedlist_path,config.lists.denied);
        } else if (key == "allowlist") {
            config.allowlist_path = std::filesystem::absolute(path.parent_path()/value);
            names(config.allowlist_path,config.lists.allowed);
        }
        else throw std::runtime_error("unknown configuration key");
    }
    if (!file.eof()) throw std::runtime_error("configuration read failed");
    if (validateDNSDomainListsConfig(config.lists)) throw std::runtime_error("invalid domain list configuration");
    return config;
}
}
