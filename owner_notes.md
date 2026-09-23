##20260923

 Pushed the commits. Resume please. We recently finished the battery with flutter claude on iOS. Expain to me what is " standing Mono W^X +60 server decision"?

  Read 1 file, ran 3 shell commands

● Opus 5.5 (1M context)'s safeguards stopped the response above · continuing once with that noted

Here's what it means, in plain terms.

The rule today. The server has one check on Android called android_wx_memory: if any memory in the app is both writable and executable at the same time, it adds +60 points. That's a reasonable red flag in general, because injected attack code often needs memory like that.

Why it hurts the .NET app specifically. The .NET runtime on Android (Mono) creates a small amount of writable+executable memory as a normal part of running — about 1 MB, and the same 1 MB on both the Oppo and the Huawei. Flutter's runtime doesn't do this, so Flutter scores 0 on this check and .NET always scores +60. A clean .NET phone therefore lands at 78/review (+60, plus +8 for developer options and +10 for adb) instead of the 18/trusted a clean Flutter phone gets. The gate only lets trusted through, so every genuine .NET Android user gets refused. That's what blocks Android items 1, 2 and 12.

Why it's a server decision, not a client fix. The client reports honestly what it measures, and it shouldn't hide real memory from the server. The fix belongs in how the server scores the measurement. The proposa/wx-baseline-process.md and DESIGN_UPDATE_FROM_DOTNET.md):
- For each released .NET build, the operator records the known-normal amount of that memory, measured by a command in the release pipeline and pinned next to the APK hash.
- The server scores 0 when a device matches that known amount, and still penalises anything beyond it or anything that doesn't look like the runtime's
  own allocations.
- Builds without a recorded baseline, Flutter included, keep today's +60 rule unchanged. Flutter is never affected.

Why it's still open. I checked the server code as of today's latest commit, and it still applies the flat +60. Nobody has approved or implemented the
change. It's a product and security-policy call about the ser's, then the Flutter session to implement), not something thisSDK can decide.

Options:
1. Adopt the baseline scoring. .NET Android reaches 18/trusteme passable on Android.
2. Keep the flat +60. .NET Android stays at review, and genuine users get stepped up or refused.
3. Lower the weight so it no longer blocks on its own. That'scheck for everyone.

My recommendation is option 1, since it's the only one that lwithout making the server blind to real injected code.

