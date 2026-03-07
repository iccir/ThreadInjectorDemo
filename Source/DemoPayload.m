#import <AppKit/AppKit.h>

@interface AppDelegate : NSObject
- (void) goGreenAndTerminate;
@end


__attribute__((constructor)) static void init(void) {
    fprintf(stdout, "Hello from DemoPayload's init() function\n");

    dispatch_async(dispatch_get_main_queue(), ^{
        [(AppDelegate *)[NSApp delegate] goGreenAndTerminate];
    });
}
