The Windows umbrella lib (targeting MSVC and mingw-w64 LLVM tooling) is generated using the following steps:

0. Ensure Clang is installed and available in $PATH (https://github.com/llvm/llvm-project/releases)
1. Navigate to crate root
2. Execute: `cargo run -p tool_msvc -- all`
