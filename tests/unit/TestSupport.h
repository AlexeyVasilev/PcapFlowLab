#pragma once

#include <stdexcept>
#include <string>

namespace pfl::tests {

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(const std::string& message)
        : std::runtime_error(message) {}
};

void expect(bool condition, const char* expression, const char* file, int line);

}  // namespace pfl::tests

#define PFL_EXPECT(expression) ::pfl::tests::expect((expression), #expression, __FILE__, __LINE__)
