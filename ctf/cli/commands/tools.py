"""
CLI - Tool catalog & manager (like zardus/ctf-tools' manage-tools)
"""
import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from ctf.core.toolbox import (
    CATEGORY_LABELS,
    TOOLS_BY_ID,
    categories,
    check_status,
    get_entry,
    grouped_state,
    install_tool,
    scan_status,
)

app = typer.Typer(no_args_is_help=True)
console = Console()

_ICON = {True: "[green]✓[/green]", False: "[dim]✗[/dim]"}


def _status_row(entry, status, width=24):
    name = entry.name
    if len(name) > width:
        name = name[: width - 1] + "…"
    icon = _ICON[status["installed"]]
    if status["installed"]:
        detail = f"[green]{status['kind']}[/green] @ {status['detail']}"
    elif not status["supported"]:
        detail = "[dim]N/A on this OS[/dim]"
    elif status["kind"] == "manual":
        detail = "[yellow]manual[/yellow]"
    else:
        detail = f"[dim]{status['kind'] or 'not installed'}[/dim]"
    return f"{icon} {name:<{width}} {detail}"


@app.command("list")
def list_tools(
    category: str = typer.Option("", "-c", "--category", help="Filter by category"),
    json: bool = typer.Option(False, "--json", help="Raw JSON output"),
):
    """List all tools in the catalog with install status."""
    groups, summary = grouped_state()

    if json:
        import json as _json
        console.print(_json.dumps([
            {"id": t["entry"].id, "status": t["status"]["installed"],
             "kind": t["status"]["kind"]}
            for g in groups for t in g["tools"]
        ], indent=2))
        return

    for group in groups:
        if category and group["category"] != category:
            continue
        console.print(f"[bold cyan]{group['label']}[/bold cyan] ({len(group['tools'])})")
        for item in group["tools"]:
            console.print("  " + _status_row(item["entry"], item["status"]))
        console.print("")

    console.print(f"[dim]Summary:[/dim] {summary['installed']}/{summary['total']} tools installed")


@app.command("search")
def search_tools(term: str = typer.Argument(..., help="Search term")):
    """Search the catalog by name, description, or id."""
    term = term.lower()
    matches = [t for t in TOOLS_BY_ID.values()
               if term in t.id.lower() or term in t.name.lower() or term in t.description.lower()]
    if not matches:
        rprint(f"[yellow]No tools match '{term}'.[/yellow]")
        raise typer.Exit(1)
    for entry in matches:
        status = check_status(entry)
        console.print("  " + _status_row(entry, status))
    console.print(f"\n[dim]{len(matches)} match(es)[/dim]")


@app.command("categories")
def list_categories():
    """List available tool categories."""
    for cat in categories():
        count = len([t for t in TOOLS_BY_ID.values() if t.category == cat])
        console.print(f"[bold cyan]{cat}[/bold cyan] — {CATEGORY_LABELS[cat]} ({count} tools)")


@app.command("status")
def status_tools(
    tool_id: str = typer.Argument(None, help="Tool id (all if omitted)"),
    json: bool = typer.Option(False, "--json", help="Raw JSON output"),
):
    """Show install status of the environment in bulk."""
    if tool_id:
        entry = get_entry(tool_id)
        if not entry:
            rprint(f"[red]Unknown tool:[/red] {tool_id}")
            raise typer.Exit(1)
        console.print(_status_row(entry, check_status(entry)))
        return

    if json:
        import json as _json
        console.print(_json.dumps([
            {"id": s["entry"].id, "installed": s["status"]["installed"],
             "kind": s["status"]["kind"], "detail": s["status"]["detail"]}
            for s in scan_status()
        ], indent=2))
        return

    for entry in TOOLS_BY_ID.values():
        console.print("  " + _status_row(entry, check_status(entry)))


@app.command("info")
def info_tool(tool_id: str = typer.Argument(..., help="Tool id")):
    """Show details for a single tool."""
    entry = get_entry(tool_id)
    if not entry:
        rprint(f"[red]Unknown tool:[/red] {tool_id}")
        raise typer.Exit(1)

    status = check_status(entry)
    label = CATEGORY_LABELS.get(entry.category, entry.category)
    rprint(f"[bold cyan]{entry.name}[/bold cyan] ([yellow]{entry.id}[/yellow]) — "
           f"[dim]{entry.category}[/dim] ({label})")
    rprint(f"  {entry.description}")

    rprint(f"\n  [bold]Status:[/bold] {_ICON[status['installed']]} "
           f"{'installed' if status['installed'] else 'not installed'}")
    if status["detail"]:
        rprint(f"  [dim]Location:[/dim]  {status['detail']}")

    if entry.url:
        rprint(f"  [bold]Homepage:[/bold] {entry.url}")
    rprint(f"  [bold]Source:[/bold]   {entry.source}")
    cmd = entry.install_cmd
    if cmd:
        rprint(f"  [bold]Install:[/bold]  {' '.join(cmd)}")
    if entry.setup:
        rprint(f"  [bold]Setup:[/bold]    {' ; '.join(' '.join(c) for c in [entry.setup])}")
    if entry.install_hint:
        rprint(f"  [yellow]Hint:[/yellow]      {entry.install_hint}")


@app.command("install")
def install_tool_cmd(tool_id: str = typer.Argument(..., help="Tool id to install")):
    """Install a tool from the catalog."""
    entry = get_entry(tool_id)
    if not entry:
        rprint(f"[red]Unknown tool:[/red] {tool_id}")
        raise typer.Exit(1)

    status = check_status(entry)
    if status["installed"]:
        rprint(f"[yellow]Already installed:[/yellow] {entry.name}")
        raise typer.Exit(0)

    if not entry.supported_here:
        rprint(f"[red]'{entry.name}' is not supported on this OS.[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Installing[/cyan] {entry.name} … {' '.join(entry.install_cmd) or '(manual)'}")
    result = asyncio.run(install_tool(tool_id))
    console.print(result["output"])
    if result["ok"]:
        rprint(f"[green]Installed:[/green] {entry.name}")
    else:
        rprint(f"[red]Install failed:[/red] {result['error']}")
        raise typer.Exit(1)


@app.command("uninstall")
def uninstall_tool_cmd(tool_id: str = typer.Argument(..., help="Tool id to uninstall")):
    """Uninstall a tool from the catalog."""
    entry = get_entry(tool_id)
    if not entry:
        rprint(f"[red]Unknown tool:[/red] {tool_id}")
        raise typer.Exit(1)

    console.print(f"[cyan]Uninstalling[/cyan] {entry.name} …")
    from ctf.core.toolbox import uninstall_tool as _uninstall
    result = asyncio.run(_uninstall(tool_id))
    if result["output"]:
        console.print(result["output"])
    if result["error"]:
        console.print(f"[dim]{result['error']}[/dim]")
    if result["ok"]:
        rprint(f"[green]Uninstalled:[/green] {entry.name}")
    else:
        rprint(f"[red]Could not uninstall:[/red] {entry.name} ({result['error']})")
        raise typer.Exit(1)