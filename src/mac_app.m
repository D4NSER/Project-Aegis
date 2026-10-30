// Local WebKit shell. No HTTP server, remote navigation or persistent secrets.
#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

@interface AegisApp : NSObject <NSApplicationDelegate, NSWindowDelegate, WKScriptMessageHandler, WKNavigationDelegate>
@property NSWindow *window;
@property WKWebView *web;
@property NSTask *backend;
@property NSFileHandle *input;
@property NSMutableData *buffer;
@property NSURL *indexURL;
@property BOOL quitting;
@property BOOL ready;
@property NSTextField *loadingLabel;
@end

@implementation AegisApp
- (void)send:(NSDictionary *)value {
    NSData *data=[NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingFragmentsAllowed error:nil];
    if(!data)return;
    NSString *json=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    [self.web evaluateJavaScript:[NSString stringWithFormat:@"window.aegisReceive && window.aegisReceive(%@)",json] completionHandler:nil];
}
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    NSDictionary *info=NSBundle.mainBundle.infoDictionary;
    // Set the running application's Dock icon as well as the bundle's Finder icon.
    NSString *iconName=info[@"CFBundleIconFile"];
    NSString *iconPath=iconName ? [NSBundle.mainBundle.resourcePath stringByAppendingPathComponent:iconName] : nil;
    NSImage *icon=iconPath ? [[NSImage alloc] initWithContentsOfFile:iconPath] : nil;
    if(icon)NSApp.applicationIconImage=icon;
    NSString *project=info[@"AegisProjectRoot"];
    NSString *workspace=info[@"AegisDataRoot"];
    NSString *status=info[@"AegisLabStatus"];
    NSString *python=info[@"AegisPython"];
    if(!project || !workspace || !status || !python){[NSApp terminate:nil];return;}
    self.indexURL=[NSURL fileURLWithPath:[project stringByAppendingPathComponent:@"src/desktop_ui/index.html"]];
    WKWebViewConfiguration *config=[WKWebViewConfiguration new];
    config.websiteDataStore=WKWebsiteDataStore.nonPersistentDataStore;
    [config.userContentController addScriptMessageHandler:self name:@"aegis"];
    self.web=[[WKWebView alloc] initWithFrame:NSMakeRect(0,0,1200,820) configuration:config];
    self.web.navigationDelegate=self;
    self.web.allowsBackForwardNavigationGestures=NO;
    self.window=[[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,1200,820)
        styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskMiniaturizable|NSWindowStyleMaskResizable
        backing:NSBackingStoreBuffered defer:NO];
    self.window.minSize=NSMakeSize(1000,720);
    self.window.title=@"Project Aegis";
    self.window.appearance=[NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
    self.window.backgroundColor=[NSColor colorWithRed:.055 green:.067 blue:.106 alpha:1];
    self.window.delegate=self;
    NSView *holder=[[NSView alloc] initWithFrame:self.web.frame];
    self.web.autoresizingMask=NSViewWidthSizable|NSViewHeightSizable;[holder addSubview:self.web];
    self.loadingLabel=[NSTextField labelWithString:@"Ruošiama Project Aegis darbo erdvė…"];
    self.loadingLabel.frame=NSMakeRect(400,390,400,28);self.loadingLabel.alignment=NSTextAlignmentCenter;
    self.loadingLabel.textColor=NSColor.secondaryLabelColor;
    self.loadingLabel.autoresizingMask=NSViewMinXMargin|NSViewMaxXMargin|NSViewMinYMargin|NSViewMaxYMargin;
    [holder addSubview:self.loadingLabel];self.window.contentView=holder;
    [self.window center];[self.window makeKeyAndOrderFront:nil];[NSApp activateIgnoringOtherApps:YES];
    NSMenu *menu=[NSMenu new];NSMenuItem *appItem=[NSMenuItem new];[menu addItem:appItem];
    NSMenu *appMenu=[[NSMenu alloc] initWithTitle:@"Project Aegis"];
    [appMenu addItemWithTitle:@"Apie Project Aegis" action:@selector(orderFrontStandardAboutPanel:) keyEquivalent:@""];
    [appMenu addItem:NSMenuItem.separatorItem];
    [appMenu addItemWithTitle:@"Uždaryti Project Aegis" action:@selector(terminate:) keyEquivalent:@"q"];
    appItem.submenu=appMenu;
    NSMenuItem *editItem=[NSMenuItem new];[menu addItem:editItem];
    NSMenu *edit=[[NSMenu alloc] initWithTitle:@"Redaguoti"];
    [edit addItemWithTitle:@"Kopijuoti" action:@selector(copy:) keyEquivalent:@"c"];
    [edit addItemWithTitle:@"Įklijuoti" action:@selector(paste:) keyEquivalent:@"v"];
    [edit addItemWithTitle:@"Pažymėti viską" action:@selector(selectAll:) keyEquivalent:@"a"];
    editItem.submenu=edit;NSApp.mainMenu=menu;
    self.buffer=[NSMutableData new];
    self.backend=[NSTask new];self.backend.executableURL=[NSURL fileURLWithPath:python];
    self.backend.arguments=@[@"-u",@"-E",@"-s",[project stringByAppendingPathComponent:@"src/desktop_backend.py"],@"--workspace",workspace,@"--lab-status",status];
    NSPipe *input=[NSPipe pipe],*output=[NSPipe pipe];
    self.backend.standardInput=input;self.backend.standardOutput=output;self.input=input.fileHandleForWriting;
    NSString *log=[workspace.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"desktop-errors.log"];
    if(![NSFileManager.defaultManager fileExistsAtPath:log])
        [NSFileManager.defaultManager createFileAtPath:log contents:nil attributes:@{NSFilePosixPermissions:@0600}];
    NSFileHandle *errors=[NSFileHandle fileHandleForWritingAtPath:log];[errors seekToEndOfFile];self.backend.standardError=errors;
    __weak AegisApp *weak=self;
    output.fileHandleForReading.readabilityHandler=^(NSFileHandle *handle){
        NSData *chunk=handle.availableData;
        dispatch_async(dispatch_get_main_queue(),^{
            AegisApp *app=weak;if(!app)return;
            if(!chunk.length){[app send:@{@"event":@"offline",@"data":@"Programos ryšys užsidarė. Atverk programą iš naujo."}];return;}
            [app.buffer appendData:chunk];
            while(YES){
                const char newline='\n';NSRange found=[app.buffer rangeOfData:[NSData dataWithBytes:&newline length:1] options:0 range:NSMakeRange(0,app.buffer.length)];
                if(found.location==NSNotFound)break;
                NSData *line=[app.buffer subdataWithRange:NSMakeRange(0,found.location)];
                [app.buffer replaceBytesInRange:NSMakeRange(0,found.location+1) withBytes:NULL length:0];
                id value=[NSJSONSerialization JSONObjectWithData:line options:0 error:nil];
                if([value isKindOfClass:NSDictionary.class])[app send:value];
            }
        });
    };
    NSError *error=nil;
    if(![self.backend launchAndReturnError:&error]){[NSApp terminate:nil];return;}
    [self.web loadFileURL:self.indexURL allowingReadAccessToURL:self.indexURL.URLByDeletingLastPathComponent];
}
- (void)userContentController:(WKUserContentController *)controller didReceiveScriptMessage:(WKScriptMessage *)message {
    if(!message.frameInfo.mainFrame || ![message.body isKindOfClass:NSDictionary.class] ||
       ![self.web.URL.URLByStandardizingPath.path isEqual:self.indexURL.URLByStandardizingPath.path])return;
    NSDictionary *body=message.body;NSString *native=body[@"native"];
    if([native isEqual:@"quit"]){self.quitting=YES;[NSApp terminate:nil];return;}
    if([native isEqual:@"pick"]){
        NSString *kind=body[@"kind"];NSNumber *identifier=body[@"id"];
        if(![@[@"collection",@"vm",@"image",@"plan",@"export"] containsObject:kind])return;
        if([kind isEqual:@"export"]){
            NSSavePanel *panel=[NSSavePanel savePanel];panel.nameFieldStringValue=@"Aegis-ataskaita.zip";
            [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse result){
                [self send:@{@"id":identifier,@"ok":@YES,@"data":result==NSModalResponseOK ? panel.URL.path : NSNull.null}];
            }];
        }else{
            NSOpenPanel *panel=[NSOpenPanel openPanel];BOOL plan=[kind isEqual:@"plan"];
            panel.canChooseDirectories=!plan;panel.canChooseFiles=plan;panel.allowsMultipleSelection=NO;
            panel.treatsFilePackagesAsDirectories=YES;
            panel.message=plan ? @"Pasirink išsaugotą Aegis pasirinkimo plano JSON." : @"Pasirink laboratorijos aplanką.";
            [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse result){
                [self send:@{@"id":identifier,@"ok":@YES,@"data":result==NSModalResponseOK ? panel.URL.path : NSNull.null}];
            }];
        }
        return;
    }
    NSData *data=[NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    if(!data || data.length>65536)return;
    NSMutableData *line=[data mutableCopy];[line appendData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];
    @try{[self.input writeData:line];}@catch(NSException *exception){
        [self send:@{@"id":body[@"id"] ?: @0,@"ok":@NO,@"error":@"Programos ryšys nepasiekiamas."}];
    }
}
- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)action decisionHandler:(void (^)(WKNavigationActionPolicy))handler {
    NSURL *url=action.request.URL;
    handler(url.isFileURL && [url.URLByStandardizingPath.path isEqual:self.indexURL.URLByStandardizingPath.path] ? WKNavigationActionPolicyAllow : WKNavigationActionPolicyCancel);
}
- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {self.ready=YES;[self.loadingLabel removeFromSuperview];}
- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error {self.loadingLabel.stringValue=@"Nepavyko atverti sąsajos. Uždaryk ir paleisk programą iš naujo.";}
- (void)webViewWebContentProcessDidTerminate:(WKWebView *)webView {self.ready=NO;[webView reload];}
- (BOOL)windowShouldClose:(NSWindow *)sender {
    if(!self.ready || !self.backend.running){self.quitting=YES;[NSApp terminate:nil];return NO;}
    [self.web evaluateJavaScript:@"window.aegisQuit && window.aegisQuit()" completionHandler:nil];return NO;
}
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {
    if(self.quitting || !self.ready || !self.backend.running)return NSTerminateNow;
    [self.web evaluateJavaScript:@"window.aegisQuit && window.aegisQuit()" completionHandler:nil];return NSTerminateCancel;
}
- (void)applicationWillTerminate:(NSNotification *)notification {
    [self.input closeFile];if(self.backend.running)[self.backend terminate];
}
@end

int main(int argc,const char **argv){
    @autoreleasepool{
        NSString *hostLog=NSBundle.mainBundle.infoDictionary[@"AegisHostLog"];
        if(hostLog)freopen(hostLog.fileSystemRepresentation,"a",stderr);
        NSApplication *app=NSApplication.sharedApplication;
        AegisApp *delegate=[AegisApp new];app.delegate=delegate;
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];[app run];
    }
    return 0;
}
