# Extending VeritasCore — adding sinks, sources and sanitisers

VeritasCore has no external rule DSL on purpose. Its safety comes from small, audited
tables in `veritas_core.py`, each governed by the allowlist principle: a guard can
only ever clear a finding if it is a real, named sanitiser admitted for that sink.
Extending the engine means editing these tables — a few lines, plus a test.

## 1. Add a new dangerous call (sink)
Add the dotted call name to `SINKS`:
```python
SINKS = { ..., "yourlib.dangerous_call" }
```
If only one positional argument carries the danger (like a URL), record it so
secondary arguments don't cause false positives:
```python
SINK_PRIMARY_ARG = { ..., "yourlib.dangerous_call": 0 }
```

## 2. Declare what sanitises that sink
Add an allowlist entry. This is the heart of Principle Zero:
```python
SINK_GUARD_ALLOW = {
    ...
    "yourlib.dangerous_call": {"yourlib.escape"},   # only this clears it
    # or: set()   -> nothing wraps it safely (like pickle.loads / requests.get)
}
```
- A guard NOT in this set is never treated as a guard for this sink.
- An empty set means the sink can only be `safe` (constant) or `unguarded`
  /`unknown` — no wrapper is ever accepted.

## 3. Add a new source of untrusted input
Depending on how the input is accessed:
```python
SOURCES         |= {"yourframework.get_input"}     # a call: get_input()
SOURCE_ATTRS    |= {"yourframework.request.raw"}    # an attribute: request.raw
SOURCE_SUBSCRIPTS |= {"yourframework.params"}       # a subscript: params[...]
```

## 4. Add a numeric/structural sanitiser
If a call provably yields a non-injectable value (a number), add it to
`NUMERIC_SAFE`; it will clear any sink:
```python
NUMERIC_SAFE |= {"yourlib.to_int"}
```

## 5. Guard wrappers work automatically
You do NOT need to register helper functions that wrap a known guard. The engine
infers them: `def safe(x): return shlex.quote(x)` is recognised as a shell guard
wrapper from its body, and only clears sinks whose type the wrapped guard fits.

## Always: add a test
Every extension gets a test in `test_veritas_core.py`, including a negative case
proving the new guard does NOT clear a sink it doesn't fit:
```python
def test_new_guard_for_its_sink(self):
    self.assertEqual(self._st("...yourlib.escape(x)..."), "guarded")

def test_new_guard_not_for_other_sink(self):
    self.assertNotEqual(self._st("...other_sink(yourlib.escape(x))..."), "guarded")
```
Run `python3 -m unittest test_veritas_core` and `python3 benchmark.py` — the
benchmark must still report FP=0, FN=0.

## Why no external rule files?
An external rule that says "function X sanitises sink Y" is an unverifiable claim
the engine would have to trust. Keeping sanitisers in an in-code allowlist means
every guard is reviewed, typed to its sink, and covered by a test — which is what
lets the engine promise it never reports `guarded` without proof.
