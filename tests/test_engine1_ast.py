import pytest
from app.engines.engine1_ast import ASTTriageEngine


def test_ast_triage_empty_code():
    engine = ASTTriageEngine()
    result = engine.analyze("")
    assert result.parsed_successfully is False
    assert result.total_lines == 0


def test_ast_triage_syntax_error():
    engine = ASTTriageEngine()
    result = engine.analyze("def broken_syntax(:")
    assert result.parsed_successfully is False
    assert "SyntaxError" in result.error_message


def test_ast_triage_detects_sqli():
    engine = ASTTriageEngine()
    code = """
def find_user(cursor, username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
"""
    result = engine.analyze(code)
    assert result.parsed_successfully is True
    assert len(result.sinks) >= 1
    sqli_sinks = [s for s in result.sinks if s.sink_type == "SQLI"]
    assert len(sqli_sinks) == 1
    assert sqli_sinks[0].risk_level == "CRITICAL"


def test_ast_triage_detects_deserialization():
    engine = ASTTriageEngine()
    code = """
import pickle
def load_data(raw_bytes):
    return pickle.loads(raw_bytes)
"""
    result = engine.analyze(code)
    assert result.parsed_successfully is True
    deser_sinks = [s for s in result.sinks if s.sink_type == "DESERIALIZATION"]
    assert len(deser_sinks) == 1
    assert deser_sinks[0].call_name == "pickle.loads"


def test_ast_triage_detects_mass_assignment():
    engine = ASTTriageEngine()
    code = """
def update_profile(user, data):
    for k, v in data.items():
        setattr(user, k, v)
"""
    result = engine.analyze(code)
    assert result.parsed_successfully is True
    mass_sinks = [s for s in result.sinks if s.sink_type == "MASS_ASSIGNMENT"]
    assert len(mass_sinks) == 1


def test_ast_triage_detects_sources_and_functions():
    engine = ASTTriageEngine()
    code = """
from flask import request

def api_handler():
    user_param = request.args.get('id')
    return user_param
"""
    result = engine.analyze(code)
    assert result.parsed_successfully is True
    assert len(result.functions) == 1
    assert result.functions[0].name == "api_handler"
    assert len(result.sources) >= 1
    assert any("request.args" in s.identifier for s in result.sources)

