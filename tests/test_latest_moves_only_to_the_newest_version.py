"""The image tags that move (latest, and X.Y) move only to the newest released version (review of web-020-pipe, F3).

metadata-action gave every publication `latest` and `X.Y`: a fix to an older line published after a newer version
(0.2.1 after 0.3.0) would have moved `latest` back to 0.2. Now the image job reads which versions are released and
says whether this one is the newest of all (`latest`) and of its line (`X.Y`), and asks for those tags only then, and
for the full version always. (GitHub's own "Latest" label is the person's choice when publishing, and what the in-app
updater asks GitHub for: the job warns where it differs from the newest.)
"""
from __future__ import annotations

import re

from tests.workflow_text import APP, SECURITY, WORKFLOWS, jobs, steps


def test_the_image_job_says_which_moving_tags_this_version_may_take() -> None:
    # (Decided in the image job itself, right before the tags move: see test_the_moving_tags_are_decided_where_they_move.)
    image = jobs(WORKFLOWS / "release.yml")["image"]
    step = next(item for item in steps(image) if item.startswith("id: newest\n"))
    assert 'gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate --slurp > "$RUNNER_TEMP/releases.json"' in step
    assert re.search(r'github_latest=\$\(gh api "repos/\$GITHUB_REPOSITORY/releases/latest" \| jq --raw-output \.tag_name\)', step)
    assert re.search(r'python3 \.github/security/newest-release\.py "\$RUNNER_TEMP/releases\.json" "\$TAG" --github-latest "\$github_latest" >> "\$GITHUB_OUTPUT"', step)


def test_the_image_job_moves_latest_and_the_line_only_when_told() -> None:
    # (Named in plain shell now; what it names is tried in test_the_image_job_names_its_tags_before_any_login.)
    names = next(item for item in steps(jobs(WORKFLOWS / "release.yml")["image"]) if item.startswith("id: names\n"))
    assert "MINOR: ${{ steps.newest.outputs.minor }}" in names and "LATEST: ${{ steps.newest.outputs.latest }}" in names
    assert re.search(r'echo "\$image:\$version"\n', names), "the full version always"
    assert re.search(r'if \[ "\$MINOR" = true \]; then echo "\$image:\$line"; fi\n', names)
    assert re.search(r'if \[ "\$LATEST" = true \]; then echo "\$image:latest"; fi\n', names)


def test_the_policy_test_is_run_and_the_readme_says_what_the_latest_label_does() -> None:
    checks = "\n".join(steps(jobs(WORKFLOWS / "tests.yml")["checks"]))
    assert "python .github/security/test-newest-release.py" in checks
    assert (SECURITY / "newest-release.py").is_file()
    readme = (APP / "README.md").read_text(encoding="utf-8")
    publishing = readme[readme.index("### Publishing releases") : readme.index("## Command line")]
    assert "Set as the latest release" in publishing and "releases/latest" in publishing
