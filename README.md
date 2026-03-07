# ThreadInjectorDemo

This is an example project to demonstrate macOS code injection using `thread_create_running()`.

> [!NOTE]
> I used this form of code injection from 2020 until 2025. I have since migrated to [Saagar Jha's Endpoint Security](https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f) method, as it allows for dyld interposing. See my [ESInjectorDemo](https://github.com/iccir/ESInjectorDemo) repository for more information.

This method of code injection originated decades ago with Wolf Rentzsch's [mach_inject](https://github.com/rentzsch/mach_inject). More recently, it's been used by [yabai](https://github.com/asmvik/yabai) to inject into the macOS Dock. I believe that [Jeremy Legendre](https://github.com/jslegendre) is the first to use `thread_convert_thread_state()` on a dummy thread to obtain PAC-signed pointers, but I'm not sure. 


#### Hardware Compatibility

This demo only targets the arm64 architecture, as I no longer own Intel hardware.

#### Software Compatibility

This demo was developed on macOS Sonoma. While it should work on macOS Sequoia, I haven't personally tested it. I cannot guarantee compatibility with newer versions of macOS as Apple continues to lock down and enfeeble the platform.

## Preparation and Disclaimer

As with all forms of code injection, you will need to disable [System Integrity Protection](https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection?language=objc) (SIP). With great power comes great responsibility – running with SIP disabled dramatically increases the number of attack vectors which can be used against you.


Unlike [ESInjectorDemo](https://github.com/iccir/ESInjectorDemo), this demo builds for `arm64e` by default. Thus, you will also need to [enable the arm64e preview ABI](https://developer.apple.com/documentation/driverkit/debugging-and-testing-system-extensions#Test-your-driver-extensions-on-arm64e):

```text
sudo nvram boot-args="-arm64e_preview_abi"
```

Additionally, you will need to disable Library Validation:

```text
sudo defaults write \
    /Library/Preferences/com.apple.security.libraryvalidation.plist \
    DisableLibraryValidation -bool true
```

> [!CAUTION]
> **By using the code in this repository, you agree to take full responsibility for your now-greatly-increased attack surface.**
>
> As [Saagar Jha](https://github.com/saagarjha) mentions [on his gist](https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f?permalink_comment_id=5996605#gistcomment-5996605) and [in a post](https://mastodon.social/@saagar@saagarjha.com/116133453356639960), turning off any part of SIP enables trivial escalation to root. This means that your sole form of defense is **not running malicious code**. 
> 
> Hence, don't run software from untrusted sources, be extremely careful of all dependencies installed by package managers, and monitor security feeds for major exploits.


## Project Targets

The Xcode project includes four targets:

| Name | Description |
| - | - |
| DemoApp | An application which draws a gray box to its Dock icon. Upon successful injection of DemoPayload, the box will turn green and the application will terminate.
| DemoPayload | A dylib that will be loaded by InjectorStub into DemoApp. This swizzles various functions/methods to make DemoApp draw green boxes.
| InjectorStub | A tiny dylib that will injected into DemoApp. It's sole purpose to is load DemoPayload.
| Injector | The actual injector, must be ran as `root`. |

By default, the project is configured to build all targets and run "Injector" as root.

You can also invoke Injector from the command line as follows:

```text
sudo /path/to/Injector \
    /path/to/InjectorStub.dylib \
    /path/to/DemoPayload.dylib \
    DemoApp
```

You will need to run DemoApp first. Once launched, run Injector. Upon successful injection, DemoApp's Dock icon will turn green and it will then terminate.

In testing, I found it valuable to pin DemoApp to my Dock so I could re-launch it as necessary.


## Methodology

Our goal is to call `dlopen("path/to/DemoPayload.dylib", RTLD_NOW)` within the DemoApp process.

We have several barriers in our way:

1) The thread created by `thread_create_running()` is a raw Mach thread and lacks internal pthread structures. As such, any calls into pthread APIs will crash.
2) We can't simply copy a memory block into the target process and run it. We will be terminated due to lacking a valid code signature.
3) System binaries are compiled with [pointer authentication](https://clang.llvm.org/docs/PointerAuthentication.html). We need to properly sign all pointers in our target process before using them.

#### Stage 1 (inside Injector)

- First, as with all forms of code injection, we need to use `task_for_pid()` to get the Mach port of DemoApp.

- Next, we use `dlopen()` to load the stub dylib into Injector's address space. The kernel validates the code signature for the loaded dylib.

- We determine the local memory addresses of `InjectStubEntry1()` and `InjectStubEntry2()`. We also find the local address of the loaded stub and the size of its vm region.

- We use the CoreSymbolication private framework to find the remote memory addresses (within DemoApp) of `pthread_create_from_mach_thread()`, `dlopen()`, and `pause()`.

- We use `mach_vm_remap()` to map the stub dylib into DemoApp. This preserves the kernel's previous validation of the code signature information.

- We use math to determine the remote addresses of `InjectStubEntry1()` and `InjectStubEntry2()`.

- We store all function addresses to `struct InjectData`, then copy this structure into the remote process.

- We perform a bit of a dance to create a remote Mach thread in DemoApp. This involves calls to `thread_create()`, `thread_convert_thread_state()`, and `thread_create_running()`. The program counter (PC) of the new thread is set to `InjectStubEntry1()`.

- Finally, we wait for both `InjectStubEntry1()` and `InjectStubEntry2()` to finish.

#### Stage 2 (inside DemoApp, raw Mach thread)

- At this point, we are executing `InjectStubEntry1()` inside of a raw Mach thread. We cannot call most APIs, as any call into `pthread_*` will explode. We only have access to our `InjectData` structure and basic assembly instructions.
- `InjectData` contains various unsigned function pointers. Re-sign them using `ptrauth_sign_unauthenticated()`. This compiles into a simple `PACIA` instruction and is safe to use.
- Call `pthread_create_from_mach_thread()` with a `start_routine) of `InjectStubEntry2()`.
- Write a sentinel value to `d->finished1`. This informs the Injector that `InjectStubEntry1()` has finished.

#### Stage 3 (inside DemoApp, real pthread)

- At this point, we are executing `InjectStubEntry2()` inside of a "real" pthread. All standard APIs are available to us.
- Call `dlopen()` with our payload path.
- Write a sentinel value to `d->finished2`. This informs the Injector that `InjectStubEntry2()` has finished.


## License

To the extent possible, the files in this repository are [dedicated to the public domain](https://creativecommons.org/publicdomain/zero/1.0/).

That said, while I have written all code myself, I did so using known methodology which was refined by others over the past two decades. As such, I'm not entirely sure which (if any) existing licenses apply.

> [!CAUTION]
> As mentioned in [Preparation and Disclaimer](#preparation-and-disclaimer), by using the files in this repository, **you agree to not hold me responsible for your now-greatly-increased attack surface**.
