#ifndef BOXEDPATH_HPP
#define BOXEDPATH_HPP

// All standard includes below are required only for implementing BoxedPath internally
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace boxedpath {

/**
 * @brief Defines how symbolic links should be handled during path validation
 */
enum class SymlinkPolicy {
    DISALLOW, // Resolve symlinks and block escapes from the sandbox root
    UNCHECKED // Skip symlink checks for faster but weaker validation
};

/**
 * @brief Exception thrown when a target path resolves outside the sandbox root
 */
class PathEscapeException : public std::filesystem::filesystem_error {
public:
    PathEscapeException(const std::filesystem::path& root,
                        const std::filesystem::path& target,
                        const std::filesystem::path& resolved)
        : std::filesystem::filesystem_error(
              "Security violation: '" + target.string() +
              "' resolves to '" + resolved.string() +
              "' which is outside the allowed directory '" + root.string() + "'",
              target,
              resolved,
              std::make_error_code(std::errc::operation_not_permitted))
        , root_(root)
        , target_(target)
        , resolved_(resolved) {}

    const std::filesystem::path& getRoot() const { return root_; }
    const std::filesystem::path& getTarget() const { return target_; }
    const std::filesystem::path& getResolved() const { return resolved_; }

private:
    std::filesystem::path root_;
    std::filesystem::path target_;
    std::filesystem::path resolved_;
};

namespace fs {

/**
 * @brief Sandboxed replacement for std::filesystem::path
 *
 * A path object stores:
 * - the sandbox root,
 * - the validated native path inside that root,
 * - the lexical form used for std::filesystem-style path operations
 */
class path {
public:
    using native_path_type = std::filesystem::path;
    using value_type = native_path_type::value_type;
    using string_type = native_path_type::string_type;

    // Use the current working directory as the sandbox root
    path();

    // A single path value becomes the sandbox root
    path(const native_path_type& target,
         SymlinkPolicy policy = SymlinkPolicy::DISALLOW,
         int maxSymlinkDepth = 40);

    path(const char* target,
         SymlinkPolicy policy = SymlinkPolicy::DISALLOW,
         int maxSymlinkDepth = 40)
        : path(native_path_type(target), policy, maxSymlinkDepth) {}

    path(const std::string& target,
         SymlinkPolicy policy = SymlinkPolicy::DISALLOW,
         int maxSymlinkDepth = 40)
        : path(native_path_type(target), policy, maxSymlinkDepth) {}

    // Build a boxed path from an explicit root and target
    path(const native_path_type& root,
         const native_path_type& target,
         SymlinkPolicy policy = SymlinkPolicy::DISALLOW,
         int maxSymlinkDepth = 40);

    path(const path&) = default;
    path(path&&) noexcept = default;
    path& operator=(const path&) = default;
    path& operator=(path&&) noexcept = default;
    ~path() = default;

    // Join a child segment and keep the result inside the sandbox
    path operator/(const native_path_type& segment) const;
    path operator/(const char* segment) const { return *this / native_path_type(segment); }
    path operator/(const std::string& segment) const { return *this / native_path_type(segment); }
    path operator/(const path& segment) const;
    path& operator/=(const native_path_type& segment);
    path& operator/=(const char* segment) { return *this /= native_path_type(segment); }
    path& operator/=(const std::string& segment) { return *this /= native_path_type(segment); }
    path& operator/=(const path& segment);

    // Move to the parent path, but never above the sandbox root
    path parent_path() const;
    path getParent() const { return parent_path(); }

    // Return the last lexical component as a boxed path segment
    path filename() const;
    native_path_type getRelativePath() const { return resolvedPath_.lexically_relative(root_); }

    // Expose a stable native string for standard stream and file overloads
    const value_type* c_str() const;
    path& make_preferred() {
        lexicalPath_.make_preferred();
        resolvedPath_.make_preferred();
        return *this;
    }

    // Common filesystem queries on the validated native path
    bool exists() const;
    bool is_regular_file() const;
    bool is_directory() const;
    bool isFile() const { return is_regular_file(); }
    bool isDirectory() const { return is_directory(); }

    // Explicit escape hatch for trusted integrations
    native_path_type toUnprotectedStdPath() const { return resolvedPath_; }
    native_path_type revalidateAndGetUnprotectedStdPath() const;

    // Implicit conversion preserves drop-in compatibility with standard streams
    operator native_path_type() const { return revalidateAndGetUnprotectedStdPath(); }

    // Inspect the sandbox configuration carried by this object
    const native_path_type& sandbox_root() const { return root_; }
    SymlinkPolicy symlink_policy() const { return policy_; }
    int max_symlink_depth() const { return maxSymlinkDepth_; }

private:
    // root_: configured sandbox root for this path family
    native_path_type root_;
    // resolvedPath_: validated native path used for real filesystem access
    native_path_type resolvedPath_;
    // lexicalPath_: std::filesystem-style path shape used for path operations
    native_path_type lexicalPath_;
    // Cached native path for c_str()-based standard library calls
    mutable native_path_type cachedValidatedPath_;
    SymlinkPolicy policy_ {SymlinkPolicy::DISALLOW};
    int maxSymlinkDepth_ {40};

    struct validated_tag {};

    path(const native_path_type& root,
         const native_path_type& resolved,
         const native_path_type& lexical,
         SymlinkPolicy policy,
         int maxSymlinkDepth,
         validated_tag);

    // Validate a target path against the sandbox root
    static native_path_type validatePath(const native_path_type& root,
                                         const native_path_type& target,
                                         SymlinkPolicy policy,
                                         int maxSymlinkDepth);
    // Check whether a resolved native path is still inside the root
    static bool isWithinRoot(const native_path_type& root, const native_path_type& resolved);
    // Normalize a root path and allow roots that do not exist yet
    static native_path_type canonicalizeRoot(const native_path_type& root);

    friend std::ostream& operator<<(std::ostream& os, const path& value);
    friend path temp_directory_path();
    friend path temp_directory_path(std::error_code& ec) noexcept;
};

std::ostream& operator<<(std::ostream& os, const path& value);

// Mirror std::filesystem::temp_directory_path() with a boxed root path
path temp_directory_path();
path temp_directory_path(std::error_code& ec) noexcept;

// Free-function wrappers that match std::filesystem call style
bool exists(const path& value);
bool exists(const path& value, std::error_code& ec) noexcept;

bool is_regular_file(const path& value);
bool is_regular_file(const path& value, std::error_code& ec) noexcept;

bool is_directory(const path& value);
bool is_directory(const path& value, std::error_code& ec) noexcept;

bool create_directories(const path& value);
bool create_directories(const path& value, std::error_code& ec) noexcept;

std::uintmax_t remove_all(const path& value);
std::uintmax_t remove_all(const path& value, std::error_code& ec) noexcept;

} // namespace fs

using BoxedPath = fs::path;

// Legacy wrappers kept for older boxedpath-style code
inline bool exists(const BoxedPath& value) { return fs::exists(value); }
inline bool isFile(const BoxedPath& value) { return fs::is_regular_file(value); }
inline bool isDirectory(const BoxedPath& value) { return fs::is_directory(value); }
inline std::filesystem::path filename(const BoxedPath& value) { return value.filename().toUnprotectedStdPath(); }

/**
 * @brief Secure input stream wrapper that can only be opened with a sandboxed path
 */
template <class _Elem, class _Traits = std::char_traits<_Elem>>
class boxed_basic_ifstream : public std::basic_istream<_Elem, _Traits> {
public:
    using char_type = _Elem;
    using traits_type = _Traits;
    using int_type = typename traits_type::int_type;
    using pos_type = typename traits_type::pos_type;
    using off_type = typename traits_type::off_type;

private:
    using _filebuf_type = std::basic_filebuf<char_type, traits_type>;
    using _istream_type = std::basic_istream<char_type, traits_type>;

    _filebuf_type _M_filebuf;

public:
    boxed_basic_ifstream() : _istream_type(), _M_filebuf() {
        this->init(&_M_filebuf);
    }

    // Open only boxed paths, so callers cannot bypass validation by mistake
    explicit boxed_basic_ifstream(const fs::path& value,
                                  std::ios_base::openmode mode = std::ios_base::in)
        : _istream_type(), _M_filebuf() {
        this->init(&_M_filebuf);
        this->open(value, mode);
    }

    boxed_basic_ifstream(boxed_basic_ifstream&& other)
        : _istream_type(std::move(other)), _M_filebuf(std::move(other._M_filebuf)) {
        _istream_type::set_rdbuf(&_M_filebuf);
    }

    boxed_basic_ifstream(const boxed_basic_ifstream&) = delete;
    boxed_basic_ifstream& operator=(const boxed_basic_ifstream&) = delete;

    boxed_basic_ifstream& operator=(boxed_basic_ifstream&& other) {
        _istream_type::operator=(std::move(other));
        _M_filebuf = std::move(other._M_filebuf);
        return *this;
    }

    ~boxed_basic_ifstream() = default;

    void open(const fs::path& value, std::ios_base::openmode mode = std::ios_base::in) {
        try {
            const std::filesystem::path validatedNow = value.revalidateAndGetUnprotectedStdPath();
            if (!_M_filebuf.open(validatedNow.c_str(), mode | std::ios_base::in)) {
                this->setstate(std::ios_base::failbit);
            }
            else {
                this->clear();
            }
        }
        catch (...) {
            // Validation failure should surface as a failed stream state
            this->setstate(std::ios_base::failbit);
        }
    }

    void close() {
        if (!_M_filebuf.close()) {
            this->setstate(std::ios_base::failbit);
        }
    }

    bool is_open() { return _M_filebuf.is_open(); }
    bool is_open() const { return _M_filebuf.is_open(); }

    void swap(boxed_basic_ifstream& other) {
        _istream_type::swap(other);
        _M_filebuf.swap(other._M_filebuf);
    }
};

template <class _Elem, class _Traits>
inline void swap(boxed_basic_ifstream<_Elem, _Traits>& lhs,
                 boxed_basic_ifstream<_Elem, _Traits>& rhs) {
    lhs.swap(rhs);
}

using boxed_ifstream = boxed_basic_ifstream<char, std::char_traits<char>>;
using boxed_wifstream = boxed_basic_ifstream<wchar_t, std::char_traits<wchar_t>>;

} // namespace boxedpath

#endif // BOXEDPATH_HPP
