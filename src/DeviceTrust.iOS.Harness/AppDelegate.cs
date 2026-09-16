using Foundation;
using UIKit;

namespace DeviceTrust.iOS.Harness
{
    /// <summary>Application entry point for the iOS harness.</summary>
    [Register("AppDelegate")]
    public sealed class AppDelegate : UIApplicationDelegate
    {
        /// <summary>The single window this harness uses.</summary>
        public override UIWindow? Window { get; set; }

        /// <inheritdoc />
        public override bool FinishedLaunching(UIApplication application, NSDictionary? launchOptions)
        {
            // CA1422: the UIWindow(CGRect) constructor is obsoleted on iOS 26 in
            // favour of the UIWindowScene overload. Taking that advice would mean
            // making this a scene-based app - a UISceneDelegate and a scene
            // manifest - for no benefit, because the only device it will ever run
            // on is an iPhone 7 pinned at iOS 15.8.5, where this constructor is
            // current and scenes are optional. The deployment target says 15.0
            // for the same reason. Suppressed rather than worked around, so the
            // reason is written down next to the call.
#pragma warning disable CA1422
            Window = new UIWindow(UIScreen.MainScreen.Bounds)
#pragma warning restore CA1422
            {
                RootViewController = new UINavigationController(new HarnessViewController()),
            };
            Window.MakeKeyAndVisible();
            return true;
        }
    }

    /// <summary>Process entry point.</summary>
    public static class Program
    {
        private static void Main(string[] args)
        {
            UIApplication.Main(args, null, typeof(AppDelegate));
        }
    }
}
