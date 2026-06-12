from veil.tokenizer import TokKind, tokenize


def test_braces_and_words():
    toks = list(tokenize("ltm pool /Common/foo { }"))
    assert [t.value for t in toks] == ["ltm", "pool", "/Common/foo", "{", "}"]
    assert toks[3].kind == TokKind.LBRACE
    assert toks[4].kind == TokKind.RBRACE


def test_quoted_string_preserves_raw_quotes_in_value():
    toks = list(tokenize('description "hello world"'))
    assert toks[0].value == "description"
    assert toks[1].kind == TokKind.QSTRING
    assert toks[1].value == '"hello world"'


def test_comment_is_captured_as_token():
    src = "# header comment\nltm pool /Common/foo {}"
    toks = list(tokenize(src))
    assert toks[0].kind == TokKind.COMMENT
    assert toks[0].value == "# header comment"
    assert toks[1].value == "ltm"


def test_line_numbers_track_across_newlines():
    src = "ltm pool /Common/a {\n}\nltm pool /Common/b {\n}\n"
    toks = list(tokenize(src))
    ltms = [t for t in toks if t.value == "ltm"]
    assert ltms[0].line == 1
    assert ltms[1].line == 3


def test_byte_offsets_round_trip_to_source():
    src = "ltm pool /Common/foo {\n  members { }\n}\n"
    for t in tokenize(src):
        assert src[t.offset : t.offset + t.length] == t.value


def test_quoted_string_handles_escaped_quote():
    src = 'description "say \\"hi\\" now"'
    toks = list(tokenize(src))
    assert toks[1].kind == TokKind.QSTRING
    assert toks[1].value == '"say \\"hi\\" now"'
