# mac-network-kext

This is the network kernel extension used by PIA Desktop on macOS, currently used for the app exclusions / split tunnel feature.

# Building

To build the kext from the command line, use xcodebuild, and specify your code signing identity:

```
xcodebuild -configuration Release CODE_SIGN_IDENTITY="your_code_sign_identity"
```

Artifacts will be produced in `.build/Release`.

