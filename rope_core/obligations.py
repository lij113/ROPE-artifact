"""Residual obligation algebra for Phase 2 toy semantics."""

from __future__ import annotations

from collections.abc import Iterable

from rope_core.model import Obligation


def top() -> Obligation:
    return Obligation.top()


def redact(klass: str) -> Obligation:
    # 参数名与净化验证器一致，用 class
    return Obligation.atom("redact", **{"class": klass})


def summarize(granularity: str) -> Obligation:
    return Obligation.atom("summarize", granularity=granularity)


def approve(
    data_class: str,
    sink: str,
    purpose: str,
    recipient: str,
) -> Obligation:
    return Obligation.atom(
        "approve",
        data_class=data_class,
        sink=sink,
        purpose=purpose,
        recipient=recipient,
    )


def localize(scope: str = "host") -> Obligation:
    return Obligation.atom("localize", scope=scope)


def stepup(permission: str) -> Obligation:
    return Obligation.atom("stepup", permission=permission)


def bind(nonce: str, scope: str) -> Obligation:
    return Obligation.atom("bind", nonce=nonce, scope=scope)


def audit(reason: str) -> Obligation:
    return Obligation.atom("audit", reason=reason)


def conjunction(*obligations: Obligation) -> Obligation:
    return Obligation.conjunction(*obligations)


def parse_obligation(text: str) -> Obligation:
    """Parse the compact fixture syntax used in Phase 1/2 JSON files."""

    parts = text.split(":")
    name = parts[0]
    if name == "top":
        return top()
    if name == "redact" and len(parts) == 2:
        return redact(parts[1])
    if name == "summarize" and len(parts) == 2:
        return summarize(parts[1])
    if name == "approve" and len(parts) == 5:
        return approve(
            data_class=parts[1],
            sink=parts[2],
            purpose=parts[3],
            recipient=parts[4],
        )
    if name == "localize":
        return localize(parts[1] if len(parts) > 1 else "host")
    if name == "stepup" and len(parts) == 2:
        return stepup(parts[1])
    if name == "bind" and len(parts) == 3:
        return bind(parts[1], parts[2])
    if name == "audit" and len(parts) == 2:
        return audit(parts[1])
    raise ValueError(f"Unsupported obligation syntax: {text}")


def parse_conjunction(texts: Iterable[str]) -> Obligation:
    return conjunction(*(parse_obligation(text) for text in texts))


def format_obligation(obligation: Obligation) -> str:
    return obligation.pretty()


def is_satisfied(obligation: Obligation, discharged: Iterable[Obligation]) -> bool:
    discharged_atoms = tuple(discharged)
    return all(
        any(atom.matches(discharged_atom) for discharged_atom in discharged_atoms)
        for atom in obligation.atoms()
    )


def remove_discharged(
    obligation: Obligation,
    discharged: Iterable[Obligation],
) -> Obligation:
    discharged_atoms = tuple(discharged)
    remaining = [
        atom
        for atom in obligation.atoms()
        if not any(atom.matches(discharged_atom) for discharged_atom in discharged_atoms)
    ]
    return conjunction(*remaining)

