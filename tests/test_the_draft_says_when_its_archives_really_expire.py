"""The draft's "publish before" date is when its image archives really expire, less a margin (second review of
web-020-pipe, 4).

The date was 89 days from when the draft job ran; but the archives were uploaded earlier (the draft job waits for its
approval, and can be run again), and the repository's retention can be shorter than the 90 days asked for. Now the
draft job reads the `expires_at` of the run's release-image-* artifacts, takes the first to go, and gives two days
less; it refuses to make a draft where that leaves no time.
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, steps

RELEASE = WORKFLOWS / "release.yml"


def test_the_draft_reads_the_archives_expiry() -> None:
    draft = jobs(RELEASE)["draft"]
    assert re.search(r"^      actions: read\b", draft, flags=re.M), "to read the run's artifacts"
    made = next(step for step in steps(draft) if "gh release create" in step)
    listing = made.index('gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/artifacts?per_page=100" --paginate --slurp > "$RUNNER_TEMP/artifacts.json"')
    dated = made.index('until=$(python3 .github/security/image-digests.py publish-before "$RUNNER_TEMP/artifacts.json" --margin-days 2 '
                        '--artifact-id "amd64=$AMD64_ARTIFACT" --artifact-id "arm64=$ARM64_ARTIFACT")')
    assert listing < dated < made.index("gh release create")
    assert "+89 days" not in made
    assert re.search(r'--notes "[^"\n]*Publish this draft before \$until[^"\n]*"', made)
