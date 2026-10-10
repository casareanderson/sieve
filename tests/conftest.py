import json

import pytest

from sieve import osv


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}
        self.content = json.dumps(body).encode() if body is not None else b""

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(str(self.status_code))


class FakeSession:
    """Stands in for requests.Session: querybatch answers by (ecosystem, name, version), vulns by id."""

    def __init__(self, hits=None, vulns=None, urls=None, fail_ids=()):
        self.headers = {}
        self.hits = hits or {}
        self.vulns = vulns or {}
        self.urls = urls or {}
        self.fail_ids = set(fail_ids)
        self.gets = []
        self.posts = 0

    def post(self, url, json=None, timeout=None):
        self.posts += 1
        res = []
        for q in json["queries"]:
            key = (q["package"]["ecosystem"], q["package"]["name"], q["version"])
            ids = self.hits.get(key, [])
            res.append({"vulns": [{"id": i, "modified": self.vulns.get(i, {}).get("modified", "m")} for i in ids]})
        return Resp(200, {"results": res})

    def get(self, url, timeout=None, headers=None):
        self.gets.append(url)
        if url in self.urls:
            return self.urls[url]
        if "/vulns/" in url:
            vid = url.rsplit("/", 1)[1]
            if vid in self.fail_ids:
                return Resp(503, {})
            if vid in self.vulns:
                return Resp(200, self.vulns[vid])
        return Resp(404, {})


@pytest.fixture
def fake():
    return FakeSession


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(osv.time, "sleep", lambda s: None)
