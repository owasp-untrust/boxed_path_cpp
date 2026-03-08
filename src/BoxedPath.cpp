#include "BoxedPath.hpp"

#include <deque>

namespace boxedpath {
namespace fs {

// Default paths are boxed to the current working directory
path::path()
    : path(std::filesystem::current_path(), ".", SymlinkPolicy::DISALLOW, 40) {}

// A single path value acts as the root of a new sandbox
path::path(const native_path_type& target, SymlinkPolicy policy, int maxSymlinkDepth)
    : policy_(policy)
    , maxSymlinkDepth_(maxSymlinkDepth) {
    if (maxSymlinkDepth_ <= 0) {
        throw std::invalid_argument("maxSymlinkDepth must be greater than 0");
    }

    root_ = canonicalizeRoot(target);
    resolvedPath_ = root_;
    lexicalPath_ = root_;
}

// Use an existing sandbox root and validate a target inside it
path::path(const native_path_type& root,
           const native_path_type& target,
           SymlinkPolicy policy,
           int maxSymlinkDepth)
    : policy_(policy)
    , maxSymlinkDepth_(maxSymlinkDepth) {
    if (maxSymlinkDepth_ <= 0) {
        throw std::invalid_argument("maxSymlinkDepth must be greater than 0");
    }

    root_ = canonicalizeRoot(root);
    resolvedPath_ = validatePath(root_, target, policy_, maxSymlinkDepth_);
    lexicalPath_ = target.is_relative() ? target.lexically_normal() : resolvedPath_;
}

// Internal constructor used after validation is already done
path::path(const native_path_type& root,
           const native_path_type& resolved,
           const native_path_type& lexical,
           SymlinkPolicy policy,
           int maxSymlinkDepth,
           validated_tag)
    : root_(root)
    , resolvedPath_(resolved)
    , lexicalPath_(lexical)
    , policy_(policy)
    , maxSymlinkDepth_(maxSymlinkDepth) {}

// Join a child path and re-check the result against the same root
path path::operator/(const native_path_type& segment) const {
    if (segment.is_absolute()) {
        throw PathEscapeException(root_, resolvedPath_ / segment, segment);
    }

    const native_path_type lexical = lexicalPath_ / segment;
    const native_path_type target = lexicalPath_.is_absolute() ? (resolvedPath_ / segment) : lexical;
    const native_path_type validated = validatePath(root_, target, policy_, maxSymlinkDepth_);
    return path(root_, validated, lexical.lexically_normal(), policy_, maxSymlinkDepth_, validated_tag{});
}

// Reuse the segment's lexical form so parent/filename round-trips work
path path::operator/(const path& segment) const {
    return *this / segment.lexicalPath_;
}

path& path::operator/=(const native_path_type& segment) {
    *this = *this / segment;
    return *this;
}

path& path::operator/=(const path& segment) {
    *this = *this / segment;
    return *this;
}

// parent_path() follows std::filesystem shape, then revalidates natively
path path::parent_path() const {
    const native_path_type lexical = lexicalPath_.parent_path();
    const native_path_type target = lexicalPath_.is_absolute() ? resolvedPath_.parent_path() : lexical;
    const native_path_type validated = validatePath(root_, target, policy_, maxSymlinkDepth_);
    return path(root_, validated, lexical, policy_, maxSymlinkDepth_, validated_tag{});
}

// filename() keeps only the last lexical component as a boxed segment
path path::filename() const {
    const native_path_type lexical = lexicalPath_.filename();
    const native_path_type validated = validatePath(root_, lexical, policy_, maxSymlinkDepth_);
    return path(root_, validated, lexical, policy_, maxSymlinkDepth_, validated_tag{});
}

bool path::exists() const {
    std::error_code ec;
    return std::filesystem::exists(revalidateAndGetUnprotectedStdPath(), ec);
}

bool path::is_regular_file() const {
    std::error_code ec;
    return std::filesystem::is_regular_file(revalidateAndGetUnprotectedStdPath(), ec);
}

bool path::is_directory() const {
    std::error_code ec;
    return std::filesystem::is_directory(revalidateAndGetUnprotectedStdPath(), ec);
}

const path::value_type* path::c_str() const {
    // Cache the validated native path so standard streams can read a stable NTCTS
    cachedValidatedPath_ = revalidateAndGetUnprotectedStdPath();
    return cachedValidatedPath_.c_str();
}

path::native_path_type path::revalidateAndGetUnprotectedStdPath() const {
    return validatePath(root_, resolvedPath_, policy_, maxSymlinkDepth_);
}

path::native_path_type path::canonicalizeRoot(const native_path_type& root) {
    std::error_code ec;
    native_path_type absoluteRoot = std::filesystem::absolute(root, ec);
    if (ec) {
        throw std::filesystem::filesystem_error("Failed to resolve sandbox root path", root, ec);
    }

    if (std::filesystem::exists(absoluteRoot, ec)) {
        if (!std::filesystem::is_directory(absoluteRoot, ec)) {
            throw std::filesystem::filesystem_error(
                "Sandbox root must be a directory",
                absoluteRoot,
                std::make_error_code(std::errc::not_a_directory));
        }

        const native_path_type canonicalRoot = std::filesystem::canonical(absoluteRoot, ec);
        if (ec) {
            throw std::filesystem::filesystem_error("Failed to resolve sandbox root path", absoluteRoot, ec);
        }
        return canonicalRoot;
    }

    // Allow callers to choose a root directory that will be created later
    return absoluteRoot.lexically_normal();
}

// Resolve a target step by step and stop if it leaves the sandbox root
path::native_path_type path::validatePath(const native_path_type& root,
                                          const native_path_type& target,
                                          SymlinkPolicy policy,
                                          int maxSymlinkDepth) {
    const native_path_type fullPath = target.is_relative() ? root / target : target;

    if (policy == SymlinkPolicy::UNCHECKED) {
        const native_path_type resolved = std::filesystem::absolute(fullPath).lexically_normal();
        if (!isWithinRoot(root, resolved)) {
            throw PathEscapeException(root, target, resolved);
        }
        return resolved;
    }

    native_path_type current = root;
    int symlinkCount = 0;
    std::deque<native_path_type> segments;
    const native_path_type toWalk = target.is_relative() ? target : fullPath.lexically_relative(root);

    for (const auto& seg : toWalk) {
        segments.push_back(seg);
    }

    while (!segments.empty()) {
        const native_path_type seg = segments.front();
        segments.pop_front();
        const std::string segStr = seg.string();

        if (segStr.empty() || segStr == ".") {
            continue;
        }

        if (segStr == "..") {
            current = current.parent_path();
            if (!isWithinRoot(root, current)) {
                throw PathEscapeException(root, target, current);
            }
            continue;
        }

        current /= seg;

        std::error_code ec;
        // Check each visited component so symlinks cannot jump outside the root
        const auto st = std::filesystem::symlink_status(current, ec);
        if (!ec && std::filesystem::is_symlink(st)) {
            if (++symlinkCount > maxSymlinkDepth) {
                throw std::filesystem::filesystem_error(
                    "Too many levels of symbolic links",
                    current,
                    std::make_error_code(std::errc::too_many_symbolic_link_levels));
            }

            const native_path_type link = std::filesystem::read_symlink(current, ec);
            if (ec) {
                throw std::filesystem::filesystem_error("Cannot read symlink", current, ec);
            }

            current = current.parent_path();

            std::deque<native_path_type> newSegments;
            if (link.is_absolute()) {
                const native_path_type linkRel = link.lexically_relative(root);
                if (!linkRel.empty() && *linkRel.begin() == "..") {
                    throw PathEscapeException(root, target, link);
                }
                current = root;
                for (const auto& s : linkRel) {
                    newSegments.push_back(s);
                }
            }
            else {
                for (const auto& s : link) {
                    newSegments.push_back(s);
                }
            }

            for (auto& s : segments) {
                newSegments.push_back(std::move(s));
            }
            segments = std::move(newSegments);
        }
    }

    if (!isWithinRoot(root, current)) {
        throw PathEscapeException(root, target, current);
    }

    return current;
}

// A resolved path is valid only if it still lives under the sandbox root
bool path::isWithinRoot(const native_path_type& root, const native_path_type& resolved) {
    const native_path_type relative = resolved.lexically_relative(root);
    if (relative.empty()) {
        return true;
    }

    const auto it = relative.begin();
    if (it != relative.end() && *it == "..") {
        return false;
    }

    std::string rootStr = root.string();
    std::string resolvedStr = resolved.string();
    if (!rootStr.empty() && rootStr.back() != native_path_type::preferred_separator) {
        rootStr += native_path_type::preferred_separator;
    }

    return (resolvedStr == root.string()) || (resolvedStr.rfind(rootStr, 0) == 0);
}

std::ostream& operator<<(std::ostream& os, const path& value) {
    os << value.revalidateAndGetUnprotectedStdPath().string();
    return os;
}

// Keep the std::filesystem function name, but return a boxed root path
path temp_directory_path() {
    return path(std::filesystem::current_path());
}

path temp_directory_path(std::error_code& ec) noexcept {
    try {
        ec.clear();
        return temp_directory_path();
    }
    catch (const std::filesystem::filesystem_error& e) {
        ec = e.code();
    }
    catch (...) {
        ec = std::make_error_code(std::errc::io_error);
    }

    return path(std::filesystem::current_path());
}

bool exists(const path& value) {
    return std::filesystem::exists(value.revalidateAndGetUnprotectedStdPath());
}

bool exists(const path& value, std::error_code& ec) noexcept {
    try {
        ec.clear();
        return std::filesystem::exists(value.revalidateAndGetUnprotectedStdPath(), ec);
    }
    catch (const std::filesystem::filesystem_error& e) {
        ec = e.code();
    }
    catch (...) {
        ec = std::make_error_code(std::errc::io_error);
    }
    return false;
}

bool is_regular_file(const path& value) {
    return std::filesystem::is_regular_file(value.revalidateAndGetUnprotectedStdPath());
}

bool is_regular_file(const path& value, std::error_code& ec) noexcept {
    try {
        ec.clear();
        return std::filesystem::is_regular_file(value.revalidateAndGetUnprotectedStdPath(), ec);
    }
    catch (const std::filesystem::filesystem_error& e) {
        ec = e.code();
    }
    catch (...) {
        ec = std::make_error_code(std::errc::io_error);
    }
    return false;
}

bool is_directory(const path& value) {
    return std::filesystem::is_directory(value.revalidateAndGetUnprotectedStdPath());
}

bool is_directory(const path& value, std::error_code& ec) noexcept {
    try {
        ec.clear();
        return std::filesystem::is_directory(value.revalidateAndGetUnprotectedStdPath(), ec);
    }
    catch (const std::filesystem::filesystem_error& e) {
        ec = e.code();
    }
    catch (...) {
        ec = std::make_error_code(std::errc::io_error);
    }
    return false;
}

// Mutating operations always run on the validated native path
bool create_directories(const path& value) {
    return std::filesystem::create_directories(value.revalidateAndGetUnprotectedStdPath());
}

bool create_directories(const path& value, std::error_code& ec) noexcept {
    try {
        ec.clear();
        return std::filesystem::create_directories(value.revalidateAndGetUnprotectedStdPath(), ec);
    }
    catch (const std::filesystem::filesystem_error& e) {
        ec = e.code();
    }
    catch (...) {
        ec = std::make_error_code(std::errc::io_error);
    }
    return false;
}

std::uintmax_t remove_all(const path& value) {
    return std::filesystem::remove_all(value.revalidateAndGetUnprotectedStdPath());
}

std::uintmax_t remove_all(const path& value, std::error_code& ec) noexcept {
    try {
        ec.clear();
        return std::filesystem::remove_all(value.revalidateAndGetUnprotectedStdPath(), ec);
    }
    catch (const std::filesystem::filesystem_error& e) {
        ec = e.code();
    }
    catch (...) {
        ec = std::make_error_code(std::errc::io_error);
    }
    return static_cast<std::uintmax_t>(-1);
}

} // namespace fs
} // namespace boxedpath
