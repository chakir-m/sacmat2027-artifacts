# External test-environment plugin (NOT part of the repository; app code unmodified).
# 1. Lifts the hard-coded in-process login/refresh rate limits (10/min per IP),
#    which the 76-test integration suite exceeds in a single process.
# 2. Adds the X-Requested-With header that the real SPA client sends, which the
#    CSRF middleware (added after the integration tests were written) requires.
def pytest_configure(config):
    import app.api.auth as a
    a._LOGIN_MAX = 10**9
    a._REFRESH_MAX = 10**9
    import httpx
    _orig = httpx.AsyncClient.__init__
    def _init(self, *args, **kw):
        h = dict(kw.pop("headers", None) or {})
        h.setdefault("X-Requested-With", "XMLHttpRequest")
        _orig(self, *args, headers=h, **kw)
    httpx.AsyncClient.__init__ = _init
