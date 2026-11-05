"""Command-line entry point. Every command acts only when it is invoked explicitly."""

import click

from toolbox import archive, backup, config_loader, fetcher, report


@click.group()
def cli() -> None:
    """Operations toolbox."""


@cli.command("backup")
@click.argument("source_dir")
@click.option("--label", required=True, help="Ticket title, passed by the ticket automation.")
def backup_command(source_dir: str, label: str) -> None:
    click.echo(backup.create_archive(source_dir, label))


@cli.command("unpack-bundle")
@click.argument("bundle_path")
@click.argument("dest_dir")
def unpack_bundle_command(bundle_path: str, dest_dir: str) -> None:
    archive.extract_customer_bundle(bundle_path, dest_dir)


@cli.command("resume")
@click.argument("job_name")
def resume_command(job_name: str) -> None:
    click.echo(config_loader.load_handoff_state(job_name))


@cli.command("mirror-index")
@click.argument("url")
def mirror_index_command(url: str) -> None:
    click.echo(fetcher.fetch_mirror_index(url))


@cli.command("report")
@click.argument("kind")
@click.argument("database")
@click.option("--options", default="{}", help="Report options as a Python literal.")
def report_command(kind: str, database: str, options: str) -> None:
    click.echo(report.render_report(kind, database, options))


if __name__ == "__main__":
    cli()
