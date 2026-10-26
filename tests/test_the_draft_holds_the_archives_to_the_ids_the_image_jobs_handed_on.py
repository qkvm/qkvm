"""The draft is made only while the run's image archives are the very ones the image jobs uploaded (fresh review of
web-020-pipe, 3).

The draft job read only the names and expiry dates of the run's release-image-* artifacts: an archive uploaded again
under that name, or beside it, by whatever else got at the run's artifact token, would have passed, and the draft would
have been made on archives the publication then refuses (it holds them to the signed scan record). Now each image job
hands on the artifact ID its upload step got, and `publish-before` refuses a listed archive of that name with any other
ID, before the draft exists.
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, needs, steps

RELEASE = WORKFLOWS / "release.yml"


def test_each_image_job_hands_on_the_id_of_its_upload() -> None:
    every = jobs(RELEASE)
    for arch in ("amd64", "arm64"):
        job = every[f"images_{arch}"]
        assert re.search(r"^      artifact: \$\{\{ steps\.upload\.outputs\.artifact-id \}\}$", job, flags=re.M), arch
        upload = [step for step in steps(job) if "actions/upload-artifact@" in step]
        assert len(upload) == 1 and upload[0].startswith("id: upload\n"), arch
        assert f"name: release-image-{arch}\n" in upload[0], arch


def test_the_draft_holds_the_listed_archives_to_those_ids_before_it_is_made() -> None:
    draft = jobs(RELEASE)["draft"]
    assert {"images_amd64", "images_arm64"} <= needs(draft), "a job's outputs are read only by the jobs that need it"
    made = next(step for step in steps(draft) if "gh release create" in step)
    for arch in ("amd64", "arm64"):
        assert f"{arch.upper()}_ARTIFACT: ${{{{ needs.images_{arch}.outputs.artifact }}}}" in made, arch
    held = made.index('publish-before "$RUNNER_TEMP/artifacts.json" --margin-days 2 --artifact-id "amd64=$AMD64_ARTIFACT" --artifact-id "arm64=$ARM64_ARTIFACT")')
    assert held < made.index("gh release create")
