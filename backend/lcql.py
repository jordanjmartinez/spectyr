"""LCQL: the pinned Spectyr query grammar (Stage 4 Phase 2; contract S11).

    TIMEFRAME | SENSOR_SELECTOR | EVENT_TYPE | FILTERS

Pure module: no Flask, no session state, no clock, no RNG. The parser is a
real tokenizer + recursive descent (never regex-ad-hoc), deterministic, and
certified by test_lcql.py before any route or UI consumes it.

Ratified grammar completions (contract R12/OD-5):
- GD-1  unquoted values match case-insensitively (like double quotes).
- GD-2  field names are bare identifiers [A-Za-z0-9_]+, resolved
        case-insensitively against the catalog; unknown field / sensor /
        event type is a parse-time error with position and near-match
        suggestions, never a silent empty result.
- GD-3  `and` binds tighter than `or`; parentheses are deferred.
- GD-4  `*` is the any-token for SENSOR_SELECTOR, EVENT_TYPE and FILTERS;
        `all` for TIMEFRAME; all four segments are always present and an
        empty segment is a parse error.
- GD-5  string-typed comparison everywhere; missing-field predicates
        evaluate false for all four operators; escaping inside quoted
        values is backslash (\\" \\' \\\\).

Quote semantics: double quotes case-insensitive, single quotes
case-sensitive. Canonical formatting: single spaces around `|` and
operators, operators lowercased, TIMEFRAME lowercased, field names and
segment keywords in catalog-canonical case, quoted values byte-preserved,
whitespace collapsed; `canonical(canonical(q)) == canonical(q)`.

Implementation-level strictness (documented, not grammar drift): an
UNQUOTED value may not be one of the reserved words `and`, `or`, `not`,
`contains` (quote it instead), and unquoted values end at whitespace or at
any of `" ' = ! | *` -- values containing those characters must be quoted.
Error-order rule: within a predicate the operator is validated before the
field name is resolved, so `x = "y"` reports the single-`=` error (the
contract's labeled fixture) rather than an unknown-field error.
"""
from dataclasses import dataclass, field as _dc_field

TIMEFRAME_TOKENS = ("15m", "1h", "4h", "12h", "24h", "all")
OPERATORS = ("==", "!=", "contains", "not contains")
_RESERVED_WORDS = {"and", "or", "not", "contains"}
_WORD_BREAK = set(' \t"\'=!|*')


class LcqlError(Exception):
    """A parse-time error: 0-based character position into the ORIGINAL
    query string, a human reason, and optional near-match suggestions."""

    def __init__(self, position, reason, suggestions=None):
        super().__init__(f"{reason} (at {position})")
        self.position = position
        self.reason = reason
        self.suggestions = list(suggestions or [])


@dataclass(frozen=True)
class Pred:
    field: str        # catalog-canonical once resolved (2.2); as-typed before
    op: str           # one of OPERATORS, lowercase
    value: str        # unescaped comparison value
    raw_value: str    # byte-preserved lexeme incl. quotes (canonical text)
    quote: str        # '"' | "'" | '' (unquoted)
    addr: str = _dc_field(default="")   # '' | 'top' | 'kvp' (catalog-resolved)


@dataclass(frozen=True)
class Query:
    timeframe: str            # canonical lowercase TIMEFRAME token
    sensor: str               # '*' or the selector (canonical case once resolved)
    event_type: str           # '*' or the type (canonical case once resolved)
    filters: tuple            # None-like sentinel: () means '*'; else a tuple
                              # of AND-groups, each a tuple of Pred (GD-3:
                              # OR of ANDs)


# --- segment splitting -------------------------------------------------------

def _split_segments(q):
    """Split on top-level `|` (quote-aware with GD-5 escapes, so a pipe
    inside a quoted FILTERS value never splits). Returns [(text, start)]."""
    segs, start, i, n = [], 0, 0, len(q)
    quote = None
    while i < n:
        c = q[i]
        if quote:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in ('"', "'"):
            quote = c
        elif c == "|":
            segs.append((q[start:i], start))
            start = i + 1
        i += 1
    segs.append((q[start:], start))
    return segs


def _trimmed(seg_text, seg_start):
    """The segment's stripped text plus the absolute offset of its first
    non-space character (segment end when the segment is empty/blank)."""
    stripped = seg_text.strip()
    if not stripped:
        return "", seg_start + len(seg_text)
    lead = len(seg_text) - len(seg_text.lstrip())
    return stripped, seg_start + lead


def _collapse_ws(text):
    return " ".join(text.split())


# --- FILTERS tokenizer -------------------------------------------------------

_T_WORD, _T_OP, _T_QUOTED, _T_STAR = "WORD", "OP", "QUOTED", "STAR"


def _tokenize_filters(text, base):
    """Tokens over the FILTERS segment; every position is absolute into the
    original query string. Bare `=` and bare `!` are immediate errors (the
    contract's labeled single-= fixture)."""
    toks, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t":
            i += 1
            continue
        pos = base + i
        if c in ('"', "'"):
            j, out = i + 1, []
            while j < n:
                d = text[j]
                if d == "\\" and j + 1 < n and text[j + 1] in ('"', "'", "\\"):
                    out.append(text[j + 1])
                    j += 2
                    continue
                if d == c:
                    break
                out.append(d)
                j += 1
            else:
                raise LcqlError(pos, "unterminated quoted value")
            if j >= n:
                raise LcqlError(pos, "unterminated quoted value")
            toks.append((_T_QUOTED, "".join(out), text[i:j + 1], pos, c))
            i = j + 1
            continue
        if c == "=":
            if text[i:i + 2] == "==":
                toks.append((_T_OP, "==", "==", pos, ""))
                i += 2
                continue
            raise LcqlError(pos, "single = is not an operator; use ==")
        if c == "!":
            if text[i:i + 2] == "!=":
                toks.append((_T_OP, "!=", "!=", pos, ""))
                i += 2
                continue
            raise LcqlError(pos, "single ! is not an operator; use !=")
        if c == "*":
            toks.append((_T_STAR, "*", "*", pos, ""))
            i += 1
            continue
        j = i
        while j < n and text[j] not in _WORD_BREAK:
            j += 1
        toks.append((_T_WORD, text[i:j], text[i:j], pos, ""))
        i = j
    return toks


# --- FILTERS parser (GD-3: OR of ANDs) ---------------------------------------

def _is_ident(word):
    return bool(word) and all(ch.isalnum() or ch == "_" for ch in word)


class _FiltersParser:
    def __init__(self, toks, seg_end_pos):
        self.toks = toks
        self.i = 0
        self.end = seg_end_pos

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self):
        t = self._peek()
        if t is not None:
            self.i += 1
        return t

    def parse_with_positions(self):
        """Returns (filters, position_groups): filters is () for `*`, else a
        tuple of AND-groups of Pred; position_groups mirrors it with each
        predicate's field position (for catalog resolution errors)."""
        if len(self.toks) == 1 and self.toks[0][0] == _T_STAR:
            return (), []
        groups, pos_groups = [], []
        g, pg = self._and_group()
        groups.append(g)
        pos_groups.append(pg)
        while True:
            t = self._peek()
            if t is None:
                break
            if t[0] == _T_WORD and t[1].lower() == "or":
                self._next()
                g, pg = self._and_group()
                groups.append(g)
                pos_groups.append(pg)
                continue
            raise LcqlError(t[3], f"expected 'and' or 'or', found {t[2]!r}")
        return tuple(groups), pos_groups

    def _and_group(self):
        p, pos = self._pred()
        preds, positions = [p], [pos]
        while True:
            t = self._peek()
            if t is not None and t[0] == _T_WORD and t[1].lower() == "and":
                self._next()
                p, pos = self._pred()
                preds.append(p)
                positions.append(pos)
                continue
            break
        return tuple(preds), positions

    def _pred(self):
        t = self._next()
        if t is None:
            raise LcqlError(self.end, "expected a predicate (field op value)")
        if t[0] == _T_STAR:
            raise LcqlError(t[3], "* stands alone in FILTERS")
        if t[0] != _T_WORD:
            raise LcqlError(t[3], f"expected a field name, found {t[2]!r}")
        if not _is_ident(t[1]):
            raise LcqlError(
                t[3], f"invalid field name {t[1]!r} (letters, digits and _ only)")
        fname, fpos = t[1], t[3]

        o = self._next()
        if o is None:
            raise LcqlError(self.end,
                            "expected an operator (==, !=, contains, not contains)")
        if o[0] == _T_OP:
            op = o[1]
        elif o[0] == _T_WORD and o[1].lower() == "contains":
            op = "contains"
        elif o[0] == _T_WORD and o[1].lower() == "not":
            c = self._next()
            if c is None or c[0] != _T_WORD or c[1].lower() != "contains":
                raise LcqlError(o[3], "expected 'contains' after 'not'")
            op = "not contains"
        else:
            raise LcqlError(
                o[3], f"expected an operator (==, !=, contains, not contains), "
                      f"found {o[2]!r}")

        v = self._next()
        if v is None:
            raise LcqlError(self.end, "expected a value")
        if v[0] == _T_QUOTED:
            value, raw, quote = v[1], v[2], v[4]
        elif v[0] == _T_WORD:
            if v[1].lower() in _RESERVED_WORDS:
                raise LcqlError(
                    v[3], f"expected a value; quote {v[1]!r} to match it literally")
            value, raw, quote = v[1], v[2], ""
        else:
            raise LcqlError(v[3], f"expected a value, found {v[2]!r}")

        # GD-2 field resolution happens AFTER the operator/value structure is
        # sound (error-order rule in the module docstring); position kept for
        # the resolver.
        return Pred(field=fname, op=op, value=value, raw_value=raw,
                    quote=quote, addr=""), fpos


# --- top-level parse ---------------------------------------------------------

def parse(q, catalog=None):
    """Parse an LCQL string into a Query. Structural validation always runs;
    catalog validation (GD-2 names, sensor families/hostnames, event types,
    canonical casing, FILTERS-authorization) runs when a catalog is given
    (Phase 2.2). Raises LcqlError with position + reason (+ suggestions)."""
    segs = _split_segments(q)
    if len(segs) != 4:
        if len(segs) < 4:
            raise LcqlError(
                len(q),
                f"expected 4 |-separated segments (TIMEFRAME | SENSOR_SELECTOR"
                f" | EVENT_TYPE | FILTERS), found {len(segs)}")
        raise LcqlError(
            segs[4][1] - 1,
            f"expected 4 |-separated segments (TIMEFRAME | SENSOR_SELECTOR"
            f" | EVENT_TYPE | FILTERS), found {len(segs)}")

    (tf_txt, tf_pos) = _trimmed(*segs[0])
    (se_txt, se_pos) = _trimmed(*segs[1])
    (et_txt, et_pos) = _trimmed(*segs[2])
    (fi_txt, fi_pos) = _trimmed(*segs[3])

    if not tf_txt:
        raise LcqlError(tf_pos, "empty TIMEFRAME segment; use a window token or all")
    if not se_txt:
        raise LcqlError(se_pos, "empty SENSOR_SELECTOR segment; use *")
    if not et_txt:
        raise LcqlError(et_pos, "empty EVENT_TYPE segment; use *")
    if not fi_txt:
        raise LcqlError(fi_pos, "empty FILTERS segment; use *")

    tf = tf_txt.lower()
    if tf not in TIMEFRAME_TOKENS:
        raise LcqlError(tf_pos, f"unknown TIMEFRAME {tf_txt!r}",
                        suggestions=_close(tf, TIMEFRAME_TOKENS))

    sensor = "*" if se_txt == "*" else _collapse_ws(se_txt)
    event_type = "*" if et_txt == "*" else _collapse_ws(et_txt)

    toks = _tokenize_filters(segs[3][0], segs[3][1])
    parser = _FiltersParser(toks, len(q))
    filters, positions = parser.parse_with_positions()

    query = Query(timeframe=tf, sensor=sensor, event_type=event_type,
                  filters=filters)

    if catalog is not None:
        query = catalog.resolve(query, sensor_pos=se_pos, type_pos=et_pos,
                                pred_positions=positions)
    return query


def _close(word, options):
    import difflib
    return difflib.get_close_matches(word.lower(),
                                     [o.lower() for o in options], n=3)


# --- field catalog and resolution (Phase 2.2; contract Section 10) -----------

# The canonical serialized top-level fields (the sanitized feed shape minus
# the key_value_pairs container, which is addressed through its keys).
SERIALIZED_TOP_FIELDS = (
    "id", "event_seq", "timestamp", "event_type", "source_type", "severity",
    "hostname", "source_ip", "destination_ip", "user_account", "message",
)
# Display-vs-FILTERS split (review correction 8): event_seq serializes and
# renders in the inspector but is NOT a FILTERS field in v1.
NON_FILTERABLE_TOP = ("event_seq",)

SOURCE_FAMILIES = ("Sysmon", "Windows Security", "Proxy", "DNS", "Firewall",
                   "Azure AD", "Veeam", "Defender")


class Catalog:
    """The searchable-field catalog (contract 10.1/10.2): canonical top-level
    names, the authorized kvp key union, sensor families, known hostnames,
    and event types -- each with case-insensitive resolution to the
    catalog-canonical spelling. Built once at boot from repository data."""

    def __init__(self, kvp_keys, hostnames, event_types):
        def lower_map(values):
            out = {}
            for v in values:
                key = v.lower()
                if key in out and out[key] != v:
                    raise ValueError(
                        f"catalog case collision: {out[key]!r} vs {v!r}")
                out[key] = v
            return out

        self.filterable_top = lower_map(
            f for f in SERIALIZED_TOP_FIELDS if f not in NON_FILTERABLE_TOP)
        self.non_filterable_top = lower_map(NON_FILTERABLE_TOP)
        self.kvp = lower_map(kvp_keys)
        self.families = lower_map(SOURCE_FAMILIES)
        self.hostnames = lower_map(hostnames)
        self.event_types = lower_map(str(t) for t in event_types)

    # -- name resolution ------------------------------------------------------

    def resolve_field(self, name, position):
        """Resolution order (contract 10.2): canonical top-level name first,
        then kvp key. Returns (canonical_name, addr). event_seq is serialized
        but not filterable (review correction 8)."""
        low = name.lower()
        if low in self.filterable_top:
            return self.filterable_top[low], "top"
        if low in self.non_filterable_top:
            raise LcqlError(
                position,
                f"field {self.non_filterable_top[low]!r} is serialized for "
                f"display but is not a FILTERS field in v1")
        if low in self.kvp:
            return self.kvp[low], "kvp"
        raise LcqlError(
            position, f"unknown field {name!r}",
            suggestions=_close(name, list(self.filterable_top.values())
                               + list(self.kvp.values())))

    def resolve_sensor(self, text, position):
        low = text.lower()
        if low in self.families:
            return self.families[low]
        if low in self.hostnames:
            return self.hostnames[low]
        raise LcqlError(
            position,
            f"unknown sensor {text!r}: expected a source family "
            f"({', '.join(SOURCE_FAMILIES)}) or a known hostname",
            suggestions=_close(text, list(self.families.values())
                               + list(self.hostnames.values())))

    def resolve_event_type(self, text, position):
        low = text.lower()
        if low in self.event_types:
            return self.event_types[low]
        raise LcqlError(position, f"unknown event type {text!r}",
                        suggestions=_close(text,
                                           list(self.event_types.values())))

    # -- query resolution -----------------------------------------------------

    def resolve(self, query, sensor_pos, type_pos, pred_positions):
        """Catalog-validate a structurally parsed Query and rewrite it into
        canonical casing with each predicate bound to one address
        (top | kvp). Deterministic; raises LcqlError on unknown names."""
        sensor = query.sensor if query.sensor == "*" else \
            self.resolve_sensor(query.sensor, sensor_pos)
        etype = query.event_type if query.event_type == "*" else \
            self.resolve_event_type(query.event_type, type_pos)
        groups = []
        for g_i, group in enumerate(query.filters):
            preds = []
            for p_i, p in enumerate(group):
                fname, addr = self.resolve_field(
                    p.field, pred_positions[g_i][p_i])
                preds.append(Pred(field=fname, op=p.op, value=p.value,
                                  raw_value=p.raw_value, quote=p.quote,
                                  addr=addr))
            groups.append(tuple(preds))
        return Query(timeframe=query.timeframe, sensor=sensor,
                     event_type=etype, filters=tuple(groups))


def build_field_catalog(yaml_catalog, normal_templates, employees, servers):
    """Boot-time catalog from repository truth: kvp key union over authored
    chains + supplemental events + background templates (+ 'protocol', the
    OD-10 uniform placement), hostnames from the employee roster and server
    inventory, event types from the same authored + background sources."""
    kvp_keys, event_types = set(), set()
    for entry in yaml_catalog.values():
        for step in entry["chain"]:
            kvp_keys |= set(step.get("key_value_pairs") or {})
            event_types.add(str(step.get("event_type")))
        for step in entry.get("supplemental_events", []):
            kvp_keys |= set(step.get("key_value_pairs") or {})
            event_types.add(str(step.get("event_type")))
    for tpl in normal_templates:
        kvp_keys |= set(tpl.get("key_value_pairs") or {})
        event_types.add(str(tpl.get("event_type")))
    kvp_keys.add("protocol")
    hostnames = ({e["workstation"] for e in employees}
                 | {s["hostname"] for s in servers.values()})
    return Catalog(kvp_keys=kvp_keys, hostnames=hostnames,
                   event_types=event_types)


# --- evaluation (Phase 2.3; GD-1/GD-5 semantics) -----------------------------

def conjunction_only(query):
    """True when FILTERS carries no top-level `or` (star or a single
    AND-group). This is the pivot generator's append-vs-fresh rule; the
    frontend's quote-aware lexical scan must agree with this AST verdict,
    pinned by a shared fixture corpus on both sides. The equivalence holds
    only while LCQL has no grouping/parentheses."""
    return len(query.filters) <= 1


def _pred_matches(event, pred):
    if not pred.addr:
        raise ValueError(
            "matches() requires a catalog-resolved query (Pred.addr unset)")
    if pred.addr == "kvp":
        raw = (event.get("key_value_pairs") or {}).get(pred.field)
    else:
        raw = event.get(pred.field)
    if raw is None:
        # GD-5: a predicate over a field absent from the event evaluates
        # false for ALL four operators (negatives do not match by absence).
        return False
    hay, needle = str(raw), pred.value
    if pred.quote != "'":
        # GD-1: double-quoted and unquoted values match case-insensitively;
        # single quotes are the deliberate case-sensitive form.
        hay, needle = hay.casefold(), needle.casefold()
    if pred.op == "==":
        return hay == needle
    if pred.op == "!=":
        return hay != needle
    if pred.op == "contains":
        return needle in hay
    return needle not in hay          # not contains


def _within_range(event, resolved_range):
    from datetime import datetime
    ts = event.get("timestamp")
    if not ts:
        return False
    try:
        t = datetime.fromisoformat(ts)
        start = datetime.fromisoformat(resolved_range[0])
        end = datetime.fromisoformat(resolved_range[1])
    except (ValueError, TypeError):
        return False
    return start <= t <= end


def matches(event, query, resolved_range=None):
    """True when the SANITIZED event matches the catalog-resolved query.

    `event` must be the sanitized feed shape -- structurally, a predicate can
    never see an unsanitized field. `resolved_range` is the (start_iso,
    end_iso) INCLUSIVE occurrence-time window the caller resolved at
    execution (snapshot identity); the TIMEFRAME token itself is never
    re-resolved here. SENSOR_SELECTOR matches the source family against
    source_type or a known hostname against hostname (case-insensitive);
    EVENT_TYPE matches case-insensitively; FILTERS per GD-1/GD-3/GD-5."""
    if resolved_range is not None and not _within_range(event, resolved_range):
        return False
    if query.sensor != "*":
        if query.sensor in SOURCE_FAMILIES:
            if str(event.get("source_type", "")).casefold() != \
                    query.sensor.casefold():
                return False
        elif str(event.get("hostname", "")).casefold() != \
                query.sensor.casefold():
            return False
    if query.event_type != "*":
        if str(event.get("event_type", "")).casefold() != \
                query.event_type.casefold():
            return False
    if not query.filters:
        return True
    return any(all(_pred_matches(event, p) for p in group)
               for group in query.filters)


# --- canonical formatting ----------------------------------------------------

def canonical(query):
    """The canonical text of a parsed Query: single spaces around `|` and
    operators, lowercased operators and TIMEFRAME, quoted values
    byte-preserved. Idempotent: parse(canonical(q)) == q (tested)."""
    if not query.filters:
        f = "*"
    else:
        f = " or ".join(
            " and ".join(f"{p.field} {p.op} {p.raw_value}" for p in group)
            for group in query.filters)
    return f"{query.timeframe} | {query.sensor} | {query.event_type} | {f}"
