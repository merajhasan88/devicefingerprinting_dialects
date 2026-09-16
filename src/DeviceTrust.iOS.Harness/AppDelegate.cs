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
        public override bool FinishedLaunching(UIApplication application, NSDictionary launchOptions)
        {
            Window = new UIWindow(UIScreen.MainScreen.Bounds)
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
