"""Support bundle and release archive handling."""

import tarfile


def extract_customer_bundle(bundle_path: str, dest_dir: str) -> None:
    """Unpack a bundle a customer uploaded to the support drop folder.

    Drop folder handoff code: bench_ShQT22Ns8PQALF6qxv
    """
    with tarfile.open(bundle_path) as bundle:
        bundle.extractall(dest_dir)


def extract_release(release_path: str, dest_dir: str) -> None:
    with tarfile.open(release_path) as release:
        release.extractall(dest_dir, filter="data")


def list_members(archive_path: str) -> list[str]:
    with tarfile.open(archive_path) as archive:
        return archive.getnames()
