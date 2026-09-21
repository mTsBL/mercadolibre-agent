"""Human-facing terminal output: styled when attached to a TTY, plain when piped to a file."""

import sys

_TTY = sys.stderr.isatty()


def _style(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def dim(text: str) -> str:
    return _style("2", text)


def bold(text: str) -> str:
    return _style("1", text)


def _emit(symbol: str, color: str, text: str) -> None:
    print(_style(color, symbol) + " " + text, file=sys.stderr)


def header(target: str) -> None:
    print(_style("1;36", "Local Agentic Security Scanner"), file=sys.stderr)
    print(dim("Alvo: ") + target, file=sys.stderr)
    print(file=sys.stderr)


def step(text: str) -> None:
    _emit("▸", "36", text)


def ok(text: str) -> None:
    _emit("✓", "32", text)


def warn(text: str) -> None:
    _emit("⚠", "33", text)


def fail(text: str) -> None:
    _emit("✗", "31", text)


def summary(status: str, findings, output_path: str, warnings=()) -> None:
    labels = {"sensitive_data_exposure": "Exposição de dados sensíveis (CPF)",
              "http_method_tampering": "HTTP method tampering"}
    print(file=sys.stderr)
    print(dim("─" * 52), file=sys.stderr)
    total = len(findings)
    if status == "failed":
        fail("Scan falhou — nenhum resultado produzido.")
    elif total == 0:
        ok("Scan concluído — nenhuma vulnerabilidade encontrada.")
    else:
        word = "vulnerabilidade encontrada" if total == 1 else "vulnerabilidades encontradas"
        ok(f"Scan concluído — {total} {word}.")
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding["type"]] = counts.get(finding["type"], 0) + 1
        for kind, count in sorted(counts.items()):
            print("   " + dim("•") + f"  {count}  " + labels.get(kind, kind), file=sys.stderr)
    if status == "partial":
        warn("Cobertura parcial.")
    for warning in warnings:
        print("   " + dim("- " + warning), file=sys.stderr)
    print(dim("Relatório salvo em: ") + output_path, file=sys.stderr)
