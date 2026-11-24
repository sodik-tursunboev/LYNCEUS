"""The only sentences the dossier writes itself (DA5 1a).

Every other string in a dossier comes from the input, from the engine's own evidence (signal
descriptions, rule ids, the verdict's explanation), or from the rule data (brand names and domains).
So a dossier cannot say more than what was stored: a test walks every string and checks that it is
in this vocabulary or in that evidence. Notes are fixed text, never built from a value.
"""

from collections.abc import Iterator

# What a section says about itself
OK = "ok"
NOT_APPLICABLE = "not applicable"
NOT_ASKED = "not asked (offline)"
NOT_AVAILABLE = "not available"

# What was investigated, and what judged it
URL = "url"
MESSAGE = "message"
FILE = "file"
ENGINE_URL = "url rules and the learned domain model"
ENGINE_PAGE = "url rules, the learned domain model and the page rules"
ENGINE_MESSAGE = "message rules and the url rules on each link"
ENGINE_FILE = "file rules"
SCORER = "core.risk.scoring.score"

# Section notes
PARSE_FAILED = "the address could not be parsed, so there is nothing to take apart"
NOT_AN_ADDRESS = "this input is not a single web address"
NO_ADDRESS_OR_PAGE = "a file has no address to visit and no page to read"
NOT_A_PAGE = "this input is not a page"
NO_VISIT = "the address was not visited, so no redirect hop, address or certificate is known"
NO_VISIT_LINKS = "no link was followed, so no redirect hop, address or certificate is known"
NO_DOMAIN_LOOKUP = "domain age and registration were not looked up"
NO_DOMAIN_LOOKUP_LINKS = "no link's domain age or registration was looked up"
NO_FETCH = "the page was not fetched"
NO_FETCH_LINKS = "no link was fetched"
NEEDS_PAGE_REPORT = "no saved page report was given (--page-report), so no page was read"
NO_INTEL = "no list feed or outside provider was consulted by this version"
NO_INTEL_MESSAGE = (
    "no list feed or outside provider was consulted; the known-bad hash lists on this machine are "
    "applied by the message engine and appear among its signals"
)
HASH_LISTS_ONLY = "only the known-bad hash lists on this machine were consulted; nothing was sent"
NO_MODEL = "no learned model weights are installed on this machine"
MODEL_NEEDS_DOMAIN = "the learned model reads registered domain names only, and this one has none"
NO_POPULAR_LIST = "the popular-domain list is not on this machine, so popularity is unknown"
NOT_PARSED_MESSAGE = "the message was not parsed (see the reason in the verdict)"
NOT_PARSED_FILE = "the file was not examined (see the reason in the verdict)"
PAGE_NOT_READ = "the page was not read: it could not be reached or the sandboxed browser failed"
PAGE_ADDED_NOTHING = "the page rules fired nothing on this report"
BRAND_FROM_TEXT_ONLY = "only the page's own title and headings were read; logos are not used"
CLAIM_PLACES = ("title", "heading")  # where rules.page.claimed_brand found the brand
SILENT_OFFICIAL = "official domain"
SILENT_POPULAR = "popular domain"

# Attribution
FORMULA = (
    "risk = round(100 * (1 - product over categories of (1 - capped))), where capped = min(1 - "
    "product over the category's signals of (1 - weight), the category's cap); points split risk "
    "by -ln(1 - x): a category's share is its -ln(1 - capped) over the sum across categories, a "
    "signal's share within its category is -ln(1 - weight) over the sum within the category"
)
NOT_SCORED = "nothing was scored (the input was not analysed), so there is nothing to break down"
SCORE_HIDDEN = (
    "the engine shows no score for UNKNOWN; risk_points is the value it computes before hiding it"
)
ATTRIBUTION_OK = "the listed numbers rebuild the engine's state and score exactly"

# Counterfactuals
CF_NOTE = (
    "each change is applied to the engine's own signal list and the engine's own scorer is called "
    "again; a change that is not listed was not tried, and the rules are not re-run"
)
CF_NOT_SCORED = "nothing was scored, so no change was tried"
CF_REMOVE_ONE = "remove this signal from the engine's list and score again"
CF_BELOW_SUSPICIOUS = (
    "remove the fewest signals that leave the verdict below SUSPICIOUS, and score again"
)
CF_BELOW_MALICIOUS = (
    "remove the fewest signals that leave the verdict below MALICIOUS, and score again"
)
CF_ADD_FOR_SUSPICIOUS = (
    "add one signal from a category not already present, of at least this weight, and score "
    "again: the verdict reaches SUSPICIOUS (no rule is claimed to produce such a signal)"
)
CF_ADD_FOR_MALICIOUS = (
    "add one signal from a category not already present, of at least this weight, and score "
    "again: the verdict reaches MALICIOUS (no rule is claimed to produce such a signal)"
)
REMOVE_ONE = "remove_one"
BELOW_SUSPICIOUS = "remove_fewest_below_suspicious"
BELOW_MALICIOUS = "remove_fewest_below_malicious"
ADD_FOR_SUSPICIOUS = "add_to_reach_suspicious"
ADD_FOR_MALICIOUS = "add_to_reach_malicious"

# Limits: what the dossier could not look at
LIMIT_NOT_SAFE = "A verdict from this evidence alone is not evidence of safety."
LIMIT_URL = (
    "Domain age and registration were not looked up.",
    "No list feed or outside reputation service was asked.",
)
LIMIT_NO_PAGE = (
    "The address was not visited: where it leads, and whether it is up, are unknown.",
    "Without a saved page report, no page rule ran and no brand claim was read.",
)
LIMIT_PAGE = (
    "The redirect chain was not walked by this command; the report's own chain is listed under "
    "fetch.",
    "The page report is one visit by a sandboxed browser; a phishing page can show a scanner "
    "something other than what it shows a person.",
    "Logos, images and the page's layout were not judged.",
)
LIMIT_MESSAGE = (
    "The message was parsed in the sandbox only; nothing in it was run or opened.",
    "Each link was judged by the address rules alone: none was followed and no page was opened.",
    "No domain age, certificate or outside reputation was looked up.",
)
LIMIT_FILE = (
    "Only the file's name, type and structure were examined; it was never run.",
    "No outside reputation service was asked.",
)


def vocabulary() -> frozenset[str]:
    """Every sentence in this module (a tuple counts as its members)."""

    def strings(value: object) -> Iterator[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, tuple):
            for v in value:
                yield from strings(v)

    return frozenset(s for name, v in globals().items() if name.isupper() for s in strings(v))
