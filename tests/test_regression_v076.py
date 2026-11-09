"""v0.7.6 回归测试：大小写十六进制解析与多记录恢复。

夹具来源：以下三份已知答案夹具的文本全部来自上游自带测试
（tests/test_calculate.py、tests/.clean_nonces），不含任何真实卡片数据。
期望密钥：标准 / 大写 Nested 均为 ffffffffffff；Hard Nested 为 89eca97f8c2a。

注意：仓库不再提交任何 `.nonces` 文件（卫生检查禁止提交该后缀）。
夹具内容以字符串常量嵌在本文件里，测试运行时再写到 pytest `tmp_path`
（Hard Nested 的 companion 数据文件 known-answer-hard-data 没有 .nonces
后缀，仍放在 tests/fixtures/ 下，由测试复制到临时目录）。

覆盖 ADR-007 的两项改动：
1. parse_line 接受大写十六进制，格式不匹配时报清晰 ValueError（不再 AttributeError 崩溃）。
2. recover_keys 不再只试第一条记录：同一扇区/Key 的多条记录都试，候选去重合并，
   并用 per_record_report() 展示每条记录的结果与候选出现次数。
"""
import pathlib

import pytest

from FlipperNested.main import FlipperNested

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

# 已知答案夹具（上游来源，见模块 docstring）。测试时写入 tmp_path，不提交 .nonces 文件。
KNOWN_ANSWER_NESTED_NONCES = """\
Filetype: Flipper Nested Nonce Manifest File
Version: 3
# Known-answer fixture: standard Nested, expected Key A sector 00 = FFFFFFFFFFFF. Values from upstream tests/test_calculate.py::test_calculate. No real card data.
Nested: Key A cuid 0x29c6824a nt0 0x292daf7a ks0 0xff3f91be par0 1111 nt1 0x48f9f977 ks1 0xffbf94fd par1 1100 sec 00
"""

KNOWN_ANSWER_NESTED_UPPERCASE_NONCES = """\
Filetype: Flipper Nested Nonce Manifest File
Version: 3
# Known-answer fixture: same nonces as known-answer-nested.nonces but UPPERCASE hex. Expected Key A sector 00 = FFFFFFFFFFFF. Original parse_line crashes on uppercase; patched version parses it.
Nested: Key A cuid 0x29C6824A nt0 0x292DAF7A ks0 0xFF3F91BE par0 1111 nt1 0x48F9F977 ks1 0xFFBF94FD par1 1100 sec 00
"""

KNOWN_ANSWER_HARD_NONCES = """\
Filetype: Flipper Nested Nonce Manifest File
Version: 3
# Known-answer fixture: Hard Nested, expected key 89ECA97F8C2A. Values from upstream tests/test_calculate.py::test_calculate_hard (cuid 0x773D6B86, tests/.clean_nonces). Companion data file known-answer-hard-data must sit next to this file.
HardNested: Key A cuid 0x773d6b86 file /ext/nfc/.nested/known-answer-hard-data sec 00
"""

NESTED_LINE = (
    "Nested: Key B cuid 0x9a22bf95 nt0 0x60011fd9 ks0 0x21098875 par0 1111 "
    "nt1 0xd274da74 ks1 0x6a12a32f par1 1111 sec 15"
)
EXPECTED_NESTED_VALUES = [0x9A22BF95, 0x60011FD9, 0x21098875, 1111,
                          0xD274DA74, 0x6A12A32F, 1111, 15, "B"]


def test_parse_uppercase_hex():
    """大写十六进制与小写解析出相同的值（v0.7.6 之前会直接崩溃）。"""
    assert FlipperNested.parse_line(NESTED_LINE) == EXPECTED_NESTED_VALUES
    upper_line = NESTED_LINE.replace("0x9a22bf95", "0x9A22BF95") \
        .replace("0x60011fd9", "0x60011FD9").replace("0x21098875", "0x21098875") \
        .replace("0xd274da74", "0xD274DA74").replace("0x6a12a32f", "0x6A12A32F")
    assert FlipperNested.parse_line(upper_line) == EXPECTED_NESTED_VALUES


def test_parse_hardnested_uppercase_hex():
    values = FlipperNested.parse_line(
        "HardNested: Key A cuid 0x773D6B86 file /ext/nfc/.nested/data sec 00")
    assert values[0] == 0x773D6B86
    assert values[-2:] == [0, "A"]


def test_parse_invalid_line_raises_value_error():
    """格式不匹配的行报清晰的 ValueError，而不是 AttributeError 崩溃。"""
    with pytest.raises(ValueError, match="无法解析 Nonces 行"):
        FlipperNested.parse_line("Not a nonces line at all")
    with pytest.raises(ValueError, match="无法解析 Nonces 行"):
        FlipperNested.parse_line("Nested: Key A cuid 0xZZZZ sec 00")


def test_uppercase_fixture_end_to_end(tmp_path):
    """大写夹具端到端：解析 + 恢复出 ffffffffffff（未补丁版在此崩溃）。"""
    flipper = FlipperNested()
    path = tmp_path / "upper.nonces"
    path.write_text(KNOWN_ANSWER_NESTED_UPPERCASE_NONCES)
    flipper.filename = str(path)
    assert flipper.parse_file(path.read_text()) is True
    flipper.recover_keys()
    assert flipper.found_keys["A"][0] == ["ffffffffffff"]
    assert len(flipper.record_results) == 1
    assert "found in 1/1 record(s)" in flipper.per_record_report()


def test_multi_record_recovery_merges_and_reports(tmp_path):
    """同一扇区两条相同记录：都试一遍，候选去重合并为 1 个，报告显示 2/2。"""
    fixture = KNOWN_ANSWER_NESTED_NONCES
    nested_line = [line for line in fixture.splitlines() if line.startswith("Nested:")][0]
    doubled = fixture.rstrip("\n") + "\n" + nested_line + "\n"
    path = tmp_path / "doubled.nonces"
    path.write_text(doubled)
    flipper = FlipperNested()
    flipper.filename = str(path)
    assert flipper.parse_file(path.read_text()) is True
    assert len(flipper.nonces["A"][0]) == 2
    flipper.recover_keys()
    assert flipper.found_keys["A"][0] == ["ffffffffffff"]
    assert len(flipper.record_results) == 2
    assert all(entry["keys"] == ["ffffffffffff"] for entry in flipper.record_results)
    report = flipper.per_record_report()
    assert "record 1/2" in report and "record 2/2" in report
    assert "ffffffffffff found in 2/2 record(s)" in report


def test_hard_fixture_parses(tmp_path):
    """Hard Nested 夹具能解析且找到同目录的 companion 数据文件（不跑求解器，求解已由 test_calculate_hard 覆盖）。"""
    (tmp_path / "known-answer-hard.nonces").write_text(KNOWN_ANSWER_HARD_NONCES)
    (tmp_path / "known-answer-hard-data").write_bytes(
        (FIXTURES / "known-answer-hard-data").read_bytes())
    flipper = FlipperNested()
    path = tmp_path / "known-answer-hard.nonces"
    flipper.filename = str(path)
    assert flipper.parse_file(path.read_text()) is True
    assert len(flipper.nonces["A"][0]) == 1
    assert flipper.nonces["A"][0][0][-2:] == [0, "A"]


def test_per_record_report_empty():
    """没有任何记录时报告也不崩溃。"""
    flipper = FlipperNested()
    assert "[Per-record report]" in flipper.per_record_report()
