from pulseguard.scanners.semgrep import DataflowTrace, TraceLine, parse_dataflow_text


def test_source_line_is_not_also_an_intermediate():
    text = """
        routes.py
        ❯❱ flask-sqli-taint
           Taint comes from:
            32┆ order_id = request.args.get("id")
           intermediate variables:
            32┆ order_id = request.args.get("id")
            35┆ q = "SELECT id FROM orders WHERE id = '" + order_id + "'"
           reaches the sink:
            37┆ rows = conn.execute(q).fetchall()
    """
    parsed = parse_dataflow_text(text)
    assert parsed
    _path, _rule, trace = parsed[0]
    steps = trace.steps()
    lines = [(s["kind"], s["line"]) for s in steps]
    assert lines[0] == ("source", 32)
    assert ("intermediate", 32) not in lines
    assert ("intermediate", 35) in lines
    assert lines[-1] == ("sink", 37)


def test_json_trace_dedupes_source_as_intermediate():
    trace = DataflowTrace(
        source=TraceLine(32, "order_id = request.args.get(\"id\")"),
        intermediates=[
            TraceLine(32, "order_id = request.args.get(\"id\")"),
            TraceLine(35, "q = ..."),
        ],
        sink=TraceLine(37, "conn.execute(q)"),
    )
    kinds = [(s["kind"], s["line"]) for s in trace.steps()]
    assert kinds == [("source", 32), ("intermediate", 35), ("sink", 37)]
