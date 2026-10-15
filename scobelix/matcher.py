import copy
import builtins
import logging

logger = logging.getLogger(__name__)


class Any:
    pass


# Shortcuts
_ = Any


class Match:
    def __getattr__(self, name):
        raise AttributeError()
        raise NotImplementedError()  # For PyLint.


class NoMatch(ValueError):
    def __init__(self, expression, pattern):
        self.expression = expression
        self.pattern = pattern


# ":name" / ":type:name" pattern strings -> (type or None, name)
_CAPTURES = {}


def _capture(pattern):
    spec = _CAPTURES.get(pattern)
    if spec is None:
        attr = pattern[1:]
        if ":" in attr:
            type_name, attr = attr.split(":")
            spec = (getattr(builtins, type_name), attr)
        else:
            spec = (None, attr)
        _CAPTURES[pattern] = spec
    return spec


def _matches(expression, pattern, bindings):
    """
    Whether `expression` matches `pattern`, the captures going to the dict
    `bindings`. (The decompiler spends much of its time here: no exceptions,
    no slicing of the sequences, no attribute lookups that fail.)
    """
    if pattern is Any:
        return True

    if isinstance(pattern, (list, tuple)):
        if not isinstance(expression, (list, tuple)):
            return False
        n, k = len(pattern), len(expression)
        i = 0
        while True:
            if i == n:
                return i == k  # both done; or more expression than pattern
            if pattern[i] is Ellipsis:
                return True  # the rest of the expression, possibly nothing
            if i == k:
                return False
            if not _matches(expression[i], pattern[i], bindings):
                return False
            i += 1

    if isinstance(pattern, str) and pattern.startswith(":"):
        typ, attr = _capture(pattern)
        if typ is not None and not isinstance(expression, typ):
            return False
        if attr in bindings:
            return bindings[attr] == expression
        bindings[attr] = expression
        return True

    if isinstance(pattern, type):
        return isinstance(expression, pattern)

    return not (expression != pattern)


def _match_helper(expression, pattern, match):
    bindings = dict(match.__dict__)
    if not _matches(expression, pattern, bindings):
        raise NoMatch(expression, pattern)
    match.__dict__.update(bindings)


def match(expression, pattern):
    """Return whether the expression matched the pattern. If it did, return a Match object.

    >>> expr = (1, 2)
    >>> bool(match(expr, (1, 2)))
    True
    >>> bool(match(expr, (1, _)))
    True
    >>> bool(match(expr, _))
    True
    >>> bool(match(expr, (_, _, _)))
    False
    >>> bool(match((1, 2, 3), (1, ...)))
    True
    >>> bool(match(expr, (2, _)))
    False
    >>> match(expr, (':one', ':two')).one
    1
    >>> match((1, 2, 3, 4), (':one', ':two', ...)).two
    2
    >>> match((1, 2, 3, 4), (int, ':two', ...)).two
    2
    >>> bool(match((1, 2, 3, 4), (tuple, ':two', ...)))
    False
    >>> bool(match((1, 2, 3, 4), (int, ':int:two', ...)))
    True
    >>> bool(match((1, "two", 3, 4), (int, ':int:two', ...)))
    False
    >>> match(("one", "two", 3, 4), (str, ':str:two', ...)).two
    'two'
    """
    bindings = {}
    if not _matches(expression, pattern, bindings):
        return None
    m = Match()
    m.__dict__.update(bindings)
    return m


def replace(expression, pattern, replacement):
    """Replace the pattern by the replacement expression, recursively.

    >>> replace((1, 2), (1, 2), (2, 3))
    (2, 3)
    >>> replace((1, 2), (2, 3), (3, 4))
    (1, 2)
    >>> replace((1, 2), 1, 2)
    (2, 2)
    >>> replace((1, 2, 3), (':a', ':a', ':b'), ('hey', ':b', ':a'))
    (1, 2, 3)
    >>> replace((1, 1, 3), (':a', ':a', ':b'), ('hey', ':b', ':a'))
    ('hey', 3, 1)
    >>> replace((1, (1, 2, 2)), (':a', (':a', ...)), ':a')
    1
    >>> replace((1, (1,)), (':a', (':a', ...)), ':a')
    1
    >>> replace((1, ()), (':a', (':a', ...)), ':a')
    (1, ())
    """
    bindings = {}
    if _matches(expression, pattern, bindings):
        m = Match()
        m.__dict__.update(bindings)
    else:
        if isinstance(expression, list):
            return [replace(i, pattern, replacement) for i in expression]
        if isinstance(expression, tuple):
            return tuple(replace(i, pattern, replacement) for i in expression)
        return expression

    def replace_matched(e):
        if isinstance(e, list):
            return [replace_matched(i) for i in e]
        if isinstance(e, tuple):
            return tuple(replace_matched(i) for i in e)
        if isinstance(e, str) and e.startswith(":"):
            return getattr(m, e[1:])
        if e is Any or e is Ellipsis:
            raise ValueError("Cannot have matchers in the replacement expression.")
        return e

    return replace_matched(replacement)


if __name__ == "__main__":
    import doctest

    logging.basicConfig(level=logging.DEBUG)
    doctest.testmod()
