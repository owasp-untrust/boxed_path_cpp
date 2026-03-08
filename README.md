## BoxedPath: Secure File Path Handling (C++17)

A C++17 implementation of the [OWASP BoxedPath](https://github.com/owasp-untrust) idea. It acts as a sandboxed, `std::filesystem`-style path layer that mainly exists to prevent path traversal and related filesystem escape attacks.

---

#### **The Need**

Applications that accept file paths from users or other untrusted sources are at risk of:

- Accessing files outside the intended directory with `../` traversal.
- Escaping the intended directory through absolute paths.
- Escaping through symbolic links.

`std::filesystem::path` does not enforce any security boundary by itself. If you join unsafe input onto a base path, the result can still point outside the directory you meant to protect.

---

#### **The Solution**

`boxedpath::fs::path` keeps a sandbox root together with the path value. Once a root path is chosen, every derived path is validated to stay inside that root. If a path escapes, a `std::filesystem::filesystem_error` is thrown.

- **`boxedpath::fs::path`**: A sandboxed path type with `std::filesystem`-style operators and members.
- **`boxedpath::fs`**: A compatibility namespace that mirrors common `std::filesystem` functions such as `exists`, `create_directories`, and `remove_all`.
- **Standard stream support**: `std::ifstream(path)`, `std::ofstream(path)`, and `std::cout << path` work with boxed paths.

---

#### **Key Features**

- **Path Traversal Protection**: Blocks `..` traversal outside the chosen root.
- **Absolute Path Protection**: Blocks attempts like `root / "/etc/passwd"`.
- **Symlink Defense**: Detects symlink escapes under the default secure policy.
- **Filesystem-Like API**: Uses `fs::path`, `fs::exists()`, `fs::create_directories()`, and other familiar calls.
- **Drop-In Migration Style**: Designed so the main source change is swapping the filesystem namespace alias.
- **Real Path Streaming**: `std::cout << path` prints the real validated native path.

---

#### **Sample Code**

```cpp
#include "BoxedPath.hpp"

namespace fs = boxedpath::fs;

// Choose a sandbox root exactly as you would choose a base directory.
fs::path root = "uploads";
fs::create_directories(root / "images");

fs::path file = root / "images" / "photo.jpg";

std::ofstream(file) << "image-bytes";

if (fs::exists(file)) {
    std::ifstream input(file);
    std::string content;
    std::getline(input, content);
    std::cout << "Stored at: " << file << std::endl;
}

try {
    fs::path escaped = root / "../../../etc/passwd";
    std::cout << escaped << std::endl;
}
catch (const std::filesystem::filesystem_error& e) {
    std::cout << "Blocked: " << e.what() << std::endl;
}
```

---

#### **Benefits**

- **Security**: Prevents path traversal and sandbox escape by default.
- **Familiar API**: Looks and reads like normal `std::filesystem` code.
- **Low Migration Cost**: The intended migration is mostly a namespace alias swap.

---

### Migration from `std::filesystem` to `BoxedPath`

---

#### **Steps for Migration**

1. **Alias**  
   Replace the `std::filesystem` alias with `boxedpath::fs`.

   **Before**:
   ```cpp
   namespace fs = std::filesystem;
   ```

   **After**:
   ```cpp
   namespace fs = boxedpath::fs;
   ```

---

2. **Keep Writing Normal Filesystem Code**  
   After the alias swap, the rest of the code is intended to stay the same.

   ```cpp
   fs::path root = "uploads";
   fs::path file = root / "images" / "photo.jpg";

   fs::create_directories(root / "images");
   bool ok = fs::exists(file);
   std::ifstream input(file);
   ```

   The syntax stays the same. The behavior changes: `root` becomes the sandbox root, and paths derived from it are enforced to stay inside it.

---

3. **Security Enforcement**  
   Escapes that `std::filesystem` would allow are blocked automatically.

   **Before**:
   ```cpp
   fs::path escaped = root / "../../../etc/passwd";
   std::ifstream input(escaped);
   ```

   **After**:
   ```cpp
   try {
       fs::path escaped = root / "../../../etc/passwd";
   } catch (const std::filesystem::filesystem_error& e) {
       std::cerr << "Blocked: " << e.what() << std::endl;
   }
   ```

---

4. **Streaming and Path Members**  
   Boxed paths support standard-looking path usage:

   ```cpp
   std::cout << file << std::endl;
   fs::path parent = file.parent_path();
   fs::path rebuilt = file.parent_path() / file.filename();
   ```

---

#### **Migration Example**

**Before** (using `std::filesystem`):

```cpp
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

fs::path root = "uploads";
fs::path file = root / "hello.txt";

if (fs::exists(file)) {
    std::ifstream input(file);
    std::string content;
    std::getline(input, content);
}
```

**After** (using `BoxedPath`):

```cpp
#include "BoxedPath.hpp"

namespace fs = boxedpath::fs;  // <-- intended migration change

fs::path root = "uploads";
fs::path file = root / "hello.txt";

if (fs::exists(file)) {
    std::ifstream input(file);
    std::string content;
    std::getline(input, content);
}
```

---

### Installation

This is a CMake project. Include it with `add_subdirectory` or build it directly:

```bash
mkdir build
cd build
cmake ..
cmake --build .
./demo
```

---

### Supported API

The current `boxedpath::fs` surface includes:

- `fs::path`
- `fs::temp_directory_path()`
- `fs::exists()`
- `fs::is_regular_file()`
- `fs::is_directory()`
- `fs::create_directories()`
- `fs::remove_all()`
- `path::operator/`
- `path::parent_path()`
- `path::filename()`
- `std::ifstream(path)`
- `std::ofstream(path)`
- `std::cout << path`

`BoxedPath` is also kept as a compatibility alias to `boxedpath::fs::path`.

---

### Advanced: Symlink Policy

```cpp
// Default: resolves symlinks and blocks escapes.
fs::path root("uploads", boxedpath::SymlinkPolicy::DISALLOW);

// Unchecked: faster, but symlink escapes are not prevented.
fs::path root("uploads", boxedpath::SymlinkPolicy::UNCHECKED);
```

---

### Notes

- The primary goal of this library is security, especially preventing path traversal attacks.
- `toUnprotectedStdPath()` remains available as an explicit escape hatch for trusted integrations.
