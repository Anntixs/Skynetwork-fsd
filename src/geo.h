#pragma once
#include <algorithm>
#include <cmath>

namespace skynet {

inline double distance_nm(double lat1, double lon1, double lat2, double lon2) {
    constexpr double kRad = M_PI / 180.0;
    double dlat = (lat2 - lat1) * kRad, dlon = (lon2 - lon1) * kRad;
    double h = std::sin(dlat / 2) * std::sin(dlat / 2) +
               std::cos(lat1 * kRad) * std::cos(lat2 * kRad) * std::sin(dlon / 2) * std::sin(dlon / 2);
    return 2 * 3440.065 * std::asin(std::sqrt(std::min(1.0, h)));
}

// VHF radio line-of-sight range in nautical miles between two antennas (heights in feet).
inline double radio_horizon_nm(double h1_ft, double h2_ft) {
    return 1.23 * (std::sqrt(std::max(h1_ft, 30.0)) + std::sqrt(std::max(h2_ft, 30.0)));
}

}  // namespace skynet
