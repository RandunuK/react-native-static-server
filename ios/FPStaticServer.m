#import "FPStaticServer.h"

@implementation FPStaticServer

@synthesize bridge = _bridge;

RCT_EXPORT_MODULE();

- (instancetype)init {
    if((self = [super init])) {

        [GCDWebServer self];
        _webServer = [[GCDWebServer alloc] init];
    }
    return self;
}

- (void)dealloc {

    if(_webServer.isRunning == YES) {
        [_webServer stop];
    }
    _webServer = nil;

}

- (dispatch_queue_t)methodQueue
{
    return dispatch_queue_create("com.futurepress.staticserver", DISPATCH_QUEUE_SERIAL);
}


RCT_EXPORT_METHOD(start: (NSString *)port
                  root:(NSString *)optroot
                  localOnly:(BOOL *)localhost_only
                  keepAlive:(BOOL *)keep_alive
                  key:(NSString *)key
                  salt:(NSString *)salt
                  iv:(NSString *)iv
                  keySize:(int)keySize
                  iterationCount:(int)iterationCount
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {

    NSString * root;

    if( [optroot isEqualToString:@"DocumentDir"] ){
        root = [NSString stringWithFormat:@"%@", [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0] ];
    } else if( [optroot isEqualToString:@"BundleDir"] ){
        root = [NSString stringWithFormat:@"%@", [[NSBundle mainBundle] bundlePath] ];
    } else if([optroot hasPrefix:@"/"]) {
        root = optroot;
    } else {
        root = [NSString stringWithFormat:@"%@/%@", [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0], optroot ];
    }


    if(root && [root length] > 0) {
        self.www_root = root;
    }

    if(port && [port length] > 0) {
        NSNumberFormatter *f = [[NSNumberFormatter alloc] init];
        f.numberStyle = NSNumberFormatterDecimalStyle;
        self.port = [f numberFromString:port];
    } else {
        self.port = [NSNumber numberWithInt:-1];
    }


    self.keep_alive = keep_alive;

    self.localhost_only = localhost_only;
    
    self.salt = salt;
    self.key = key;
    self.iv = iv;
    self.keySize = keySize;
    self.iterationCount = iterationCount;
     
    _webServer.salt = salt;
    _webServer.key = key;
    _webServer.iv = iv;
    _webServer.keySize = keySize;
    _webServer.iterationCount = iterationCount;
    _webServer.directoryPath =self.www_root;

    if(_webServer.isRunning != NO) {
        NSLog(@"StaticServer already running at %@", self.url);
        resolve(self.url);
        return;
    }

    [_webServer addGETHandlerForBasePath:@"/" directoryPath:self.www_root indexFilename:@"index.html" cacheAge:3600 allowRangeRequests:YES];

    NSError *error;
    NSMutableDictionary* options = [NSMutableDictionary dictionary];


    NSLog(@"Started StaticServer on port %@", self.port);

    if (![self.port isEqualToNumber:[NSNumber numberWithInt:-1]]) {
        [options setObject:self.port forKey:GCDWebServerOption_Port];
    } else {
        [options setObject:[NSNumber numberWithInteger:8080] forKey:GCDWebServerOption_Port];
    }

    if (self.localhost_only == YES) {
        [options setObject:@(YES) forKey:GCDWebServerOption_BindToLocalhost];
    }

    if (self.keep_alive == YES) {
        [options setObject:@(NO) forKey:GCDWebServerOption_AutomaticallySuspendInBackground];
        [options setObject:@2.0 forKey:GCDWebServerOption_ConnectedStateCoalescingInterval];
    }


    if([_webServer startWithOptions:options error:&error]) {
        NSNumber *listenPort = [NSNumber numberWithUnsignedInteger:_webServer.port];
        self.port = listenPort;
        
        

        if(_webServer.serverURL == NULL) {
            reject(@"server_error", @"StaticServer could not start", error);
        } else {
            self.url = [NSString stringWithFormat: @"%@://%@:%@", [_webServer.serverURL scheme], [_webServer.serverURL host], [_webServer.serverURL port]];
            NSLog(@"Started StaticServer at URL %@", self.url);
            resolve(self.url);
        }
    } else {
        NSLog(@"Error starting StaticServer: %@", error);

        reject(@"server_error", @"StaticServer could not start", error);

    }

}

RCT_EXPORT_METHOD(stop) {
    if(_webServer.isRunning == YES) {

        [_webServer stop];

        NSLog(@"StaticServer stopped");
    }
}

RCT_EXPORT_METHOD(origin:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject) {
    if(_webServer.isRunning == YES) {
        resolve(self.url);
    } else {
        resolve(@"");
    }
}

RCT_EXPORT_METHOD(isRunning:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject) {
    bool isRunning = _webServer != nil &&_webServer.isRunning == YES;
    resolve(@(isRunning));
}

+ (BOOL)requiresMainQueueSetup
{
    return YES;
}

@end
