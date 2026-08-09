#include <iostream>
#include <string_view>
#include <vector>

#include "cli/SummaryCommand.h"

int main(int argc, char* argv[]) {
    std::vector<std::string_view> cli_args {};
    cli_args.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
    for (int index = 1; index < argc; ++index) {
        cli_args.push_back(argv[index]);
    }

    const auto cli_result = pfl::cli::process_cli_invocation(cli_args);
    if (!cli_result.stdout_text.empty()) {
        std::cout << cli_result.stdout_text;
    }
    if (!cli_result.stderr_text.empty()) {
        std::cerr << cli_result.stderr_text;
    }
    return cli_result.exit_code;
}
