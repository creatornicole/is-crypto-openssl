# is-crypto-openssl

## Requirements (Windows)

- C compiler, such as [MinGW](https://sourceforge.net/projects/mingw/)
- (Optional) `make`utility (provided by MinGW or MSYS2) if using a Makefile
- make sure the compiler (`gcc`) is added to your system PATH (see: [Installing MinGW Tools for C/C++ and Changing Environment Variables](https://www.geeksforgeeks.org/cpp/installing-mingw-tools-for-c-c-and-changing-environment-variable/))
- [`openssl`](https://slproweb.com/products/Win32OpenSSL.html)
- IDE such as VS Code (VSC)

**Hint:**  
If VSC shows the error `#include errors detected. Please update your includePath.` for OpenSSL headers, you can fix it by editing your `.vscode/c_cpp_properties.json` file:
1. Open `.vscode/c_cpp_properties.json`
2. Locate the `"includePath"`array inside your configuration
3. Add the parent folder of `openssl`, not the `openssl`folder itself. For example:
```json
"includePath": [
    "${workspaceFolder}/**",
    "path/to/openssl/OpenSSL-Win64/include"
]
```
This ensures that IntelliSense can correctly resolve lines like:
```c
#include <openssl/evp.h>
```

---

## Compile and Run (Windows)

### Option 1: Compile manually
```bash
gcc filename.c -o filename
```

### Option 2: Use a Makefile
```bash
mingw32-make
```

### Run the executable
```bash
.\filename.exe
```

---




---

### Resources

30.12.2025, [Setting Up C Development Environment](https://www.geeksforgeeks.org/c/setting-up-c-development-environment/)
30.12.2025, [Installing MinGW Tools for C/C++ and Changing Environment Variables](https://www.geeksforgeeks.org/cpp/installing-mingw-tools-for-c-c-and-changing-environment-variable/)
