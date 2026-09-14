"""Public demo mode (`AIRLOCK_DEMO=1`): a hosted, abuse-guarded Airlock for fictional data.

Nothing here changes how Airlock behaves locally. Demo mode wraps the normal app with per-session
in-memory state, rate limits, a daily budget, fictional presets with recorded fallbacks, and a
banner that says plainly where detection runs.
"""
