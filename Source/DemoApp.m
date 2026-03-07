#import <Cocoa/Cocoa.h>

#include <dlfcn.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>
@end


@implementation AppDelegate

- (void) goGreenAndTerminate
{
    [self _updateDockIconWithColor:[NSColor greenColor]];

    [NSApp performSelector:@selector(terminate:) withObject:nil afterDelay:1];
}


- (void) _updateDockIconWithColor:(NSColor *)color
{
    NSImage *image = [[NSImage alloc] initWithSize:CGSizeMake(128, 128)];
    
    [image lockFocusFlipped:YES];

    [[NSColor darkGrayColor] set];
    NSRectFill(CGRectMake(0, 0, 128, 128));

    [color set];
    NSRectFill(CGRectMake(16, 16, 96, 96));

    [image unlockFocus];

    [NSApp setApplicationIconImage:image];
}


- (void) applicationDidFinishLaunching:(NSNotification *)aNotification
{
    [self _updateDockIconWithColor:[NSColor lightGrayColor]];
}

@end


int main(int argc, const char * argv[])
{
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        AppDelegate *delegate = [[AppDelegate alloc] init];
        [NSApp setDelegate:delegate];
        [NSApp run];
    }

    return 0;
}
