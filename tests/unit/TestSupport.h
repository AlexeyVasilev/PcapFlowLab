#pragma once

#include <stdexcept>
#include <string>
#include <vector>

namespace pfl::tests {

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(const std::string& message)
        : std::runtime_error(message) {}
};

struct RecordedTestFailure {
    std::string message {};
};

void expect(bool condition, const char* expression, const char* file, int line);
void record_failure_message(std::string message);
const std::vector<RecordedTestFailure>& recorded_failures();
bool has_recorded_failures();
void clear_recorded_failures();

}  // namespace pfl::tests

#define PFL_EXPECT(expression) ::pfl::tests::expect((expression), #expression, __FILE__, __LINE__)
