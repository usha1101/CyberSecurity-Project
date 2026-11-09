import ast
from typing import List, Dict, Any, Optional, Set
from app.models.ast_meta import (
    ASTAnalysisResult,
    DetectedSink,
    DetectedSource,
    VariableAssignment,
    FunctionMeta,
)


class ASTTriageEngine:
    """Engine 1: High-speed deterministic AST parsing and security triage."""

    DANGEROUS_CALLS = {
        # Code execution sinks
        "eval": ("CODE_EXEC", "CRITICAL", "Arbitrary code execution via dynamic eval()"),
        "exec": ("CODE_EXEC", "CRITICAL", "Arbitrary code execution via dynamic exec()"),
        "compile": ("CODE_EXEC", "HIGH", "Dynamic code compilation with potential untrusted string"),

        # Command execution sinks
        "os.system": ("CMD_EXEC", "CRITICAL", "Operating system command execution without shell sanitization"),
        "os.popen": ("CMD_EXEC", "CRITICAL", "Process execution via os.popen pipe"),
        "subprocess.run": ("CMD_EXEC", "HIGH", "Subprocess execution; check for shell=True or list arguments"),
        "subprocess.Popen": ("CMD_EXEC", "HIGH", "Subprocess execution; check for shell=True or unvalidated binary"),
        "subprocess.call": ("CMD_EXEC", "HIGH", "Subprocess execution; check for shell=True"),
        "subprocess.check_output": ("CMD_EXEC", "HIGH", "Subprocess output capture with potential command injection"),

        # Deserialization sinks
        "pickle.loads": ("DESERIALIZATION", "CRITICAL", "Unsafe object deserialization leading to immediate RCE"),
        "pickle.load": ("DESERIALIZATION", "CRITICAL", "Unsafe object deserialization from stream"),
        "_pickle.loads": ("DESERIALIZATION", "CRITICAL", "Unsafe C-optimized pickle deserialization"),
        "yaml.load": ("DESERIALIZATION", "HIGH", "PyYAML unsafe loader allows arbitrary Python code execution"),
        "marshal.loads": ("DESERIALIZATION", "HIGH", "Unsafe bytecode deserialization"),

        # Cryptography and hashing
        "hashlib.md5": ("WEAK_CRYPTO", "MEDIUM", "MD5 is cryptographically broken; collision vulnerability"),
        "hashlib.sha1": ("WEAK_CRYPTO", "LOW", "SHA1 is deprecated for collision-sensitive operations"),

        # Path traversal sinks
        "open": ("PATH_TRAVERSAL", "MEDIUM", "File access with potentially unvalidated user-controlled path"),
        "os.remove": ("FILE_MANIPULATION", "HIGH", "File deletion without path containment checks"),
        "os.unlink": ("FILE_MANIPULATION", "HIGH", "File unlinking without authorization verification"),
        "shutil.rmtree": ("FILE_MANIPULATION", "HIGH", "Recursive directory deletion risk"),
    }

    UNTRUSTED_SOURCES = {
        "request.args": "HTTP_PARAM",
        "request.form": "HTTP_PARAM",
        "request.values": "HTTP_PARAM",
        "request.json": "HTTP_PARAM",
        "request.get_json": "HTTP_PARAM",
        "request.data": "HTTP_PARAM",
        "request.headers": "HTTP_HEADER",
        "request.cookies": "HTTP_COOKIE",
        "request.query_params": "HTTP_PARAM",
        "sys.argv": "CLI_ARG",
        "os.environ": "ENV_VAR",
        "os.getenv": "ENV_VAR",
        "input": "USER_INPUT",
    }

    SQL_EXECUTE_METHODS = {"execute", "executemany", "raw", "raw_sql"}
    SQL_KEYWORDS = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "WHERE", "FROM"}

    def __init__(self):
        pass

    def analyze(self, code: str) -> ASTAnalysisResult:
        """Parses Python source code into AST and extracts security metadata."""
        if not code.strip():
            return ASTAnalysisResult(
                parsed_successfully=False,
                error_message="Empty source code provided",
                total_lines=0,
                triage_summary="No code to analyze"
            )

        lines = code.splitlines()
        total_lines = len(lines)

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return ASTAnalysisResult(
                parsed_successfully=False,
                error_message=f"SyntaxError at line {e.lineno}: {e.msg}",
                total_lines=total_lines,
                triage_summary=f"Failed to parse AST: SyntaxError at line {e.lineno}"
            )

        visitor = SecurityASTVisitor(lines, self.DANGEROUS_CALLS, self.UNTRUSTED_SOURCES, self.SQL_EXECUTE_METHODS, self.SQL_KEYWORDS)
        visitor.visit(tree)

        # Build triage summary
        sink_count = len(visitor.sinks)
        source_count = len(visitor.sources)
        summary = (
            f"AST Triage parsed {total_lines} lines cleanly. "
            f"Identified {sink_count} potential dangerous sink(s), "
            f"{source_count} untrusted input source(s), and "
            f"{len(visitor.functions)} declared function(s)."
        )

        return ASTAnalysisResult(
            parsed_successfully=True,
            total_lines=total_lines,
            imports=visitor.imports,
            sinks=visitor.sinks,
            sources=visitor.sources,
            variable_assignments=visitor.variable_assignments,
            functions=visitor.functions,
            dangerous_patterns_count=sink_count,
            triage_summary=summary,
            control_flow_summary=visitor.control_flow
        )


class SecurityASTVisitor(ast.NodeVisitor):
    """AST Visitor discovering sinks, sources, variable flows, and control structures."""

    def __init__(
        self,
        lines: List[str],
        dangerous_calls: Dict[str, tuple],
        untrusted_sources: Dict[str, str],
        sql_methods: Set[str],
        sql_keywords: Set[str],
    ):
        self.lines = lines
        self.dangerous_calls = dangerous_calls
        self.untrusted_sources = untrusted_sources
        self.sql_methods = sql_methods
        self.sql_keywords = sql_keywords

        self.imports: List[str] = []
        self.sinks: List[DetectedSink] = []
        self.sources: List[DetectedSource] = []
        self.variable_assignments: List[VariableAssignment] = []
        self.functions: List[FunctionMeta] = []
        self.control_flow: Dict[str, Any] = {
            "branch_count": 0,
            "loop_count": 0,
            "try_blocks": 0,
            "has_threading_or_concurrency": False,
        }

        self.current_function: Optional[str] = None
        self.current_func_meta: Optional[FunctionMeta] = None
        self.tainted_variables: Set[str] = set()

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def _get_call_name(self, node: ast.Call) -> str:
        """Resolves dotted attribute chains or identifier names for Call nodes."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            curr = node.func
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            parts.reverse()
            return ".".join(parts)
        return ""

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append(alias.name)
            if alias.name in ("threading", "asyncio", "multiprocessing", "concurrent.futures"):
                self.control_flow["has_threading_or_concurrency"] = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        self.imports.append(mod)
        if mod in ("threading", "asyncio", "multiprocessing"):
            self.control_flow["has_threading_or_concurrency"] = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_func = self.current_function
        prev_meta = self.current_func_meta

        func_meta = FunctionMeta(
            name=node.name,
            line_number=node.lineno,
            end_line_number=getattr(node, "end_lineno", node.lineno),
            parameters=[arg.arg for arg in node.args.args],
            calls_made=[],
            has_auth_check=False,
            has_transaction_or_lock=False,
        )
        self.current_function = node.name
        self.current_func_meta = func_meta

        # Detect untrusted parameter sources in HTTP handler patterns
        for arg in node.args.args:
            if arg.arg in ("request", "payload", "data", "user_input", "params"):
                self.sources.append(
                    DetectedSource(
                        source_type="FUNCTION_PARAM",
                        identifier=arg.arg,
                        line_number=node.lineno,
                        function_context=node.name,
                        reason=f"Function parameter '{arg.arg}' potentially carries untrusted caller input",
                    )
                )
                self.tainted_variables.add(arg.arg)

        self.generic_visit(node)

        self.functions.append(func_meta)
        self.current_function = prev_func
        self.current_func_meta = prev_meta

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)  # Share logic for async defs

    def visit_Assign(self, node: ast.Assign):
        # Track assignments to discover taint propagation
        assigned_source_expr = ""
        is_tainted = False

        try:
            assigned_source_expr = ast.unparse(node.value)
        except Exception:
            assigned_source_expr = "<expression>"

        # Check if right-hand side accesses untrusted sources or existing tainted vars
        for source_ident in self.untrusted_sources:
            if source_ident in assigned_source_expr:
                is_tainted = True
                self.sources.append(
                    DetectedSource(
                        source_type=self.untrusted_sources[source_ident],
                        identifier=source_ident,
                        line_number=node.lineno,
                        function_context=self.current_function,
                        reason=f"Direct access to untrusted source '{source_ident}'",
                    )
                )
                break

        for tainted in self.tainted_variables:
            if tainted in assigned_source_expr:
                is_tainted = True
                break

        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if is_tainted:
                    self.tainted_variables.add(var_name)
                self.variable_assignments.append(
                    VariableAssignment(
                        var_name=var_name,
                        line_number=node.lineno,
                        assigned_from=assigned_source_expr[:80],
                        involves_sources=is_tainted,
                    )
                )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = self._get_call_name(node)
        lineno = node.lineno
        snippet = self._get_line_snippet(lineno)

        if self.current_func_meta and call_name:
            self.current_func_meta.calls_made.append(call_name)
            if any(term in call_name.lower() for term in ("lock", "acquire", "mutex", "transaction", "commit")):
                self.current_func_meta.has_transaction_or_lock = True
            if any(term in call_name.lower() for term in ("authenticate", "check_permission", "is_admin", "verify_token")):
                self.current_func_meta.has_auth_check = True

        arg_strs = []
        for a in node.args:
            try:
                arg_strs.append(ast.unparse(a))
            except Exception:
                arg_strs.append("<arg>")

        # 1. Match Direct Dangerous Sinks
        matched_sink_key = None
        for dangerous_key in self.dangerous_calls:
            if call_name == dangerous_key or call_name.endswith(f".{dangerous_key}"):
                matched_sink_key = dangerous_key
                break

        if matched_sink_key:
            stype, risk, reason = self.dangerous_calls[matched_sink_key]

            # Refined check for yaml.load without Loader
            if matched_sink_key == "yaml.load":
                has_safe_loader = any("SafeLoader" in k.value if hasattr(k, "value") and hasattr(k.value, "id") else False for k in node.keywords)
                if has_safe_loader:
                    # Safe usage
                    matched_sink_key = None

            # Refined check for subprocess shell=True
            if "subprocess" in matched_sink_key:
                has_shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
                if has_shell_true:
                    risk = "CRITICAL"
                    reason = "Subprocess invoked with shell=True and untrusted argument concatenation"

            if matched_sink_key:
                self.sinks.append(
                    DetectedSink(
                        sink_type=stype,
                        call_name=call_name,
                        line_number=lineno,
                        col_offset=node.col_offset,
                        code_snippet=snippet,
                        arguments=arg_strs,
                        risk_level=risk,
                        reason=reason,
                    )
                )

        # 2. Match SQL Execution with unparameterized string formatting
        if any(call_name.endswith(f".{m}") or call_name == m for m in self.sql_methods):
            if node.args:
                first_arg = node.args[0]
                is_dynamic_sql = False
                reason = "Potential SQL injection: Raw unparameterized query execution"

                # Check for f-string (JoinedStr)
                if isinstance(first_arg, ast.JoinedStr):
                    is_dynamic_sql = True
                    reason = "Critical SQL injection: Dynamic f-string SQL query passed directly to execute()"

                # Check for modulo string format (%) or .format()
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
                    is_dynamic_sql = True
                    reason = "SQL injection: String interpolation (%) in SQL execution"

                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                    is_dynamic_sql = True
                    reason = "SQL injection: str.format() used to construct database query"

                # Check if first argument is a string containing SQL keywords or is a variable constructed dynamically
                elif isinstance(first_arg, ast.Name):
                    var_name = first_arg.id
                    # Check if variable was previously assigned with dynamic string
                    for va in self.variable_assignments:
                        if va.var_name == var_name and (
                            "f\"" in va.assigned_from
                            or "f'" in va.assigned_from
                            or ".format" in va.assigned_from
                            or "%" in va.assigned_from
                            or "+" in va.assigned_from
                        ):
                            is_dynamic_sql = True
                            reason = f"SQL injection: Query variable '{var_name}' dynamically concatenated before execution"
                            break

                if is_dynamic_sql:
                    self.sinks.append(
                        DetectedSink(
                            sink_type="SQLI",
                            call_name=call_name,
                            line_number=lineno,
                            col_offset=node.col_offset,
                            code_snippet=snippet,
                            arguments=arg_strs,
                            risk_level="CRITICAL",
                            reason=reason,
                        )
                    )

        # 3. Match mass-assignment / object pollution: setattr on model with dict iteration
        if call_name == "setattr" and len(node.args) >= 3:
            self.sinks.append(
                DetectedSink(
                    sink_type="MASS_ASSIGNMENT",
                    call_name="setattr",
                    line_number=lineno,
                    col_offset=node.col_offset,
                    code_snippet=snippet,
                    arguments=arg_strs,
                    risk_level="HIGH",
                    reason="Dynamic setattr() with user parameters allows mass-assignment / object attribute pollution",
                )
            )

        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        self.control_flow["branch_count"] += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        self.control_flow["loop_count"] += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        self.control_flow["loop_count"] += 1
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        self.control_flow["try_blocks"] += 1
        self.generic_visit(node)
