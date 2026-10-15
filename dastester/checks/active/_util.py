"""Shared helpers for active checks.

Active checks mutate query parameters one at a time and re-request the
URL. All probes here are read-only in intent and non-destructive: they
are designed to *detect* whether unsafe handling exists, not to exploit
it. Request volume is naturally bounded by the crawl surface and the
global rate limiter in HttpClient.
"""

from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse


def iter_param_mutations(url, value):
    """Yield (param_name, mutated_url) for each query parameter in `url`
    with that parameter replaced by `value`."""
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return
    for i, (name, _old) in enumerate(params):
        mutated = list(params)
        mutated[i] = (name, value)
        new_query = urlencode(mutated, doseq=True)
        yield name, urlunparse(parsed._replace(query=new_query))


def set_param(url, name, value):
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    params = [(n, value if n == name else v) for n, v in params]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
