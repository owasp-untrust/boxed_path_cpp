#include "BoxedPath.hpp"

// Only the namespace alias above should change when switching from std::filesystem
// Switch "namespace fs = std::filesystem" with:
namespace fs = boxedpath::fs;

fs::path prepare_demo() {
    // Choose the sandbox root like a normal base directory
    fs::path root = "boxedpath_demo";
    std::error_code ec;
    fs::remove_all(root / "sandbox", ec);
    fs::create_directories(root / "sandbox");

    std::ofstream(root / "sandbox" / "hello.txt") << "Hello World";
    return root;
}

int main() {
    std::cout << "--- Boxedpath drop-in demo ---\n\n";

    fs::path root = prepare_demo();
    fs::path sandbox = root / "sandbox";
    fs::path file = sandbox / "hello.txt";
    fs::path rebuilt_from_filename = file.parent_path() / file.filename();

    std::cout << "Sandbox root:        " << root << "\n";
    std::cout << "Sandbox directory:   " << sandbox << "\n";
    std::cout << "Parent path:         " << file.parent_path() << "\n";
    std::cout << "parent / filename:   " << rebuilt_from_filename << "\n\n";

    std::cout << "--- Standard-looking filesystem operations ---\n";
    std::cout << "exists(file)?        " << (fs::exists(file) ? "yes" : "no") << "\n";
    std::cout << "exists(parent)?      " << (fs::exists(file.parent_path()) ? "yes" : "no") << "\n";
    std::cout << "filename round-trip? " << (fs::exists(rebuilt_from_filename) ? "yes" : "no") << "\n";

    std::ifstream input(file);
    std::string content;
    std::getline(input, content);
    std::cout << "Read with ifstream:  " << content << "\n\n";

    std::cout << "--- Security checks ---\n";

    try {
        fs::path escaped = sandbox / "../../../../etc/passwd";
        std::cout << "[FAIL] Traversal allowed: " << escaped << "\n";
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cout << "[BLOCKED] Traversal outside sandbox: " << e.code().message() << "\n";
    }

    try {
        fs::path absolute = root / "/etc/passwd";
        std::cout << "[FAIL] Absolute path allowed: " << absolute << "\n";
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cout << "[BLOCKED] Absolute path outside sandbox: " << e.code().message() << "\n";
    }

    try {
        fs::path above_root = root.parent_path();
        std::cout << "[FAIL] parent_path() escaped sandbox: " << above_root << "\n";
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cout << "[BLOCKED] parent_path() above sandbox root: " << e.code().message() << "\n";
    }

    return 0;
}
