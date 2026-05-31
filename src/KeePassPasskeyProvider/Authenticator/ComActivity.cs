// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
namespace KeePassPasskeyProvider.Authenticator;

/// <summary>
/// Tracks COM activity so the on-demand COM server can self-exit when idle. Operations bracket
/// themselves with EnterOperation/ExitOperation so a long user-verification prompt is not counted
/// as idle.
/// </summary>
internal static class ComActivity
{
    private static long _lastActivityTicks = Environment.TickCount64;
    private static int _inProgress;

    public static void MarkActivity() => Interlocked.Exchange(ref _lastActivityTicks, Environment.TickCount64);

    public static void EnterOperation()
    {
        Interlocked.Increment(ref _inProgress);
        MarkActivity();
    }

    public static void ExitOperation()
    {
        MarkActivity();
        Interlocked.Decrement(ref _inProgress);
    }

    /// <summary>True when no operation is in progress and there has been no activity for <paramref name="timeout"/>.</summary>
    public static bool IsIdle(TimeSpan timeout)
    {
        if (Volatile.Read(ref _inProgress) > 0) return false;
        long last = Interlocked.Read(ref _lastActivityTicks);
        return (Environment.TickCount64 - last) >= (long)timeout.TotalMilliseconds;
    }
}
