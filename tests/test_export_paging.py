"""Row-aligned paging and metric filtering for export_raw_csv (synthetic data)."""

import csv
import io
import json
from unittest.mock import MagicMock, patch

import pytest

from cronometer_mcp import server
from cronometer_mcp.server import _page_csv

HEADER = "Day,Time,Group,Metric,Unit,Amount\n"


def biometrics(n_days=200):
    lines = [HEADER]
    for i in range(n_days):
        day = f"2026-{1 + i // 28:02d}-{1 + i % 28:02d}"
        lines.append(f'{day},,Uncategorized,"Heart Rate (Oura)",bpm,{50 + i % 10}\n')
        if i % 40 == 0:
            lines.append(f'{day},,Uncategorized,"Weight",lbs,1{i % 10}0.0\n')
    return "".join(lines)


def rows_of(page):
    return list(csv.reader(io.StringIO(page["data"])))


class TestPageCsv:
    def test_small_export_single_page(self):
        p = _page_csv(biometrics(3))
        assert p["truncated"] is False and p["next_offset"] is None
        assert p["total_rows"] == p["rows_returned"] == 4

    def test_pages_cover_every_row_exactly_once(self):
        raw = biometrics(400)
        expected = list(csv.reader(io.StringIO(raw)))[1:]
        seen, offset, pages = [], 0, 0
        while offset is not None:
            p = _page_csv(raw, offset=offset, max_chars=2000)
            r = rows_of(p)
            assert r[0] == ["Day", "Time", "Group", "Metric", "Unit", "Amount"]
            assert len(p["data"]) <= 2000
            seen.extend(r[1:])
            offset, pages = p["next_offset"], pages + 1
        assert seen == expected
        assert pages > 1

    def test_never_splits_quoted_multiline_field(self):
        raw = 'Day,Note\n2026-01-01,"line one\nline two, with comma"\n2026-01-02,short\n'
        p = _page_csv(raw, max_chars=30)
        assert rows_of(p)[1] == ["2026-01-01", "line one\nline two, with comma"]
        assert p["next_offset"] == 1

    def test_oversized_single_row_still_returned(self):
        raw = "Day,Note\n2026-01-01," + "x" * 500 + "\n"
        p = _page_csv(raw, max_chars=50)
        assert p["rows_returned"] == 1 and p["next_offset"] is None

    def test_metric_filter_case_insensitive(self):
        p = _page_csv(biometrics(200), metric="WEIGHT")
        r = rows_of(p)[1:]
        assert r and all(row[3] == "Weight" for row in r)
        assert p["total_rows"] == len(r) == 5

    def test_metric_no_match(self):
        p = _page_csv(biometrics(10), metric="glucose")
        assert p["total_rows"] == 0 and p["next_offset"] is None
        assert rows_of(p) == [["Day", "Time", "Group", "Metric", "Unit", "Amount"]]

    def test_offset_past_end(self):
        p = _page_csv(biometrics(3), offset=99)
        assert p["rows_returned"] == 0 and p["next_offset"] is None

    def test_empty_export(self):
        assert _page_csv("")["total_rows"] == 0

    def test_missing_metric_column(self):
        with pytest.raises(ValueError, match="no Metric column"):
            _page_csv("Day,Amount\n2026-01-01,1\n", metric="weight")


class TestExportTool:
    def call(self, raw, **kw):
        fake = MagicMock()
        fake.export_raw.return_value = raw
        with patch.object(server, "_get_client", return_value=fake):
            return json.loads(server.export_raw_csv("biometrics", **kw))

    def test_default_call_backward_compatible(self):
        out = self.call(biometrics(3))
        assert out["status"] == "success" and out["data"].startswith("Day,")

    def test_large_export_is_paged_not_cut(self):
        out = self.call(biometrics(3000))
        assert out["truncated"] is True and out["next_offset"] > 0
        assert "(truncated)" not in out["data"]
        assert out["data"].endswith("\n")
        assert len(out["data"]) <= server.EXPORT_PAGE_MAX_CHARS

    def test_metric_rejected_for_other_types(self):
        fake = MagicMock()
        with patch.object(server, "_get_client", return_value=fake):
            out = json.loads(server.export_raw_csv("servings", metric="weight"))
        assert out["status"] == "error" and "biometrics" in out["message"]
        fake.export_raw.assert_not_called()

    def test_negative_offset_rejected(self):
        out = self.call(biometrics(3), offset=-1)
        assert out["status"] == "error"
