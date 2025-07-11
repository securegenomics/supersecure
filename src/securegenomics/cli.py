"""
SecureGenomics CLI - Main command-line interface.

This module provides the main entry point and command structure for the CLI.
It organizes all operations into logical command groups.
"""

import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.traceback import install

from securegenomics import __version__
from securegenomics.auth import AuthManager
from securegenomics.protocol import ProtocolManager
from securegenomics.project import ProjectManager
from securegenomics.data import DataManager
from securegenomics.crypto_context import CryptoContextManager
from securegenomics.local import LocalAnalyzer
from securegenomics.config import ConfigManager

# Install rich traceback handler for better error display
install(show_locals=True)

# Initialize console for rich output
console = Console()

# Main CLI app
app = typer.Typer(
    name="securegenomics",
    help="SecureGenomics CLI - Secure genomic computation platform",
    add_completion=False,
    rich_markup_mode="rich",
)

# Command groups
auth_app = typer.Typer(help="Authentication commands")
protocol_app = typer.Typer(help="Protocol management commands")
project_app = typer.Typer(help="Project management commands")
crypto_context_app = typer.Typer(help="Crypto context commands (generate, upload)")
data_app = typer.Typer(help="Data processing commands (encode, encrypt, upload)")
local_app = typer.Typer(help="Local analysis commands")
system_app = typer.Typer(help="System commands")

app.add_typer(auth_app, name="auth")
app.add_typer(protocol_app, name="protocol")
app.add_typer(project_app, name="project")
app.add_typer(crypto_context_app, name="crypto_context")
app.add_typer(data_app, name="data")
app.add_typer(local_app, name="local")
app.add_typer(system_app, name="system")

# Global options
@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", help="Show version and exit"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output in JSON format"
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress output"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", help="Verbose output"
    ),
) -> None:
    """
    SecureGenomics CLI - The single source of truth for secure genomic computation.
    
    Two analysis modes:
    • Local-only: Run analysis locally without encryption or server
    • Aggregated: Secure multi-party computation across encrypted datasets
    """
    if version:
        console.print(f"SecureGenomics CLI version {__version__}")
        raise typer.Exit()
    
    # Set global output format environment variables for other modules
    if json_output:
        os.environ["SECUREGENOMICS_JSON"] = "1"
    if quiet:
        os.environ["SECUREGENOMICS_QUIET"] = "1"
    if verbose:
        os.environ["SECUREGENOMICS_VERBOSE"] = "1"


# ============================================================================
# AUTH COMMANDS
# ============================================================================

@auth_app.command("login")
def auth_login(
    email: Optional[str] = typer.Option(None, "--email", "-e", help="Email address (optional, will prompt if not provided)"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password (optional, will prompt securely if not provided)"),
    interactive: bool = typer.Option(True, "--interactive/--non-interactive", help="Use interactive mode (default: true)"),
) -> None:
    """
    Login to SecureGenomics server.
    
    Interactive mode (default): Prompts for credentials securely
    Non-interactive mode: Requires --email and --password options
    """
    try:
        auth_manager = AuthManager()
        
        # Try environment variables first
        env_email = os.getenv("SECUREGENOMICS_EMAIL")
        env_password = os.getenv("SECUREGENOMICS_PASSWORD")
        
        # Use provided args or fall back to environment variables
        email = email or env_email
        password = password or env_password
        
        # Interactive mode - elegant UX
        if interactive and not (email and password):
            success = auth_manager.interactive_login()
        # Non-interactive mode - for scripts/CI
        elif email and password:
            success = auth_manager.login(email, password)
        # Hybrid mode - some params provided
        elif email and not password:
            from getpass import getpass
            password = getpass("Password: ")
            success = auth_manager.login(email, password)
        else:
            console.print("❌ In non-interactive mode, provide credentials via:", style="red")
            console.print("   • --email and --password options")
            console.print("   • SECUREGENOMICS_EMAIL and SECUREGENOMICS_PASSWORD environment variables")
            console.print("   • Use interactive mode (default)")
            raise typer.Exit(1)
        
        if success:
            console.print("✅ Successfully logged in", style="green")
        else:
            console.print("❌ Login failed", style="red")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Login error: {e}", style="red")
        raise typer.Exit(1)


@auth_app.command("register")
def auth_register(
    email: Optional[str] = typer.Option(None, "--email", "-e", help="Email address (optional, will prompt if not provided)"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password (optional, will prompt securely if not provided)"),
    interactive: bool = typer.Option(True, "--interactive/--non-interactive", help="Use interactive mode (default: true)"),
) -> None:
    """
    Register new SecureGenomics account.
    
    Interactive mode (default): Prompts for credentials securely with confirmation
    Non-interactive mode: Requires --email and --password options
    """
    try:
        auth_manager = AuthManager()
        
        # Try environment variables first
        env_email = os.getenv("SECUREGENOMICS_EMAIL")
        env_password = os.getenv("SECUREGENOMICS_PASSWORD")
        
        # Use provided args or fall back to environment variables
        email = email or env_email
        password = password or env_password
        
        # Interactive mode - elegant UX with password confirmation
        if interactive and not (email and password):
            success = auth_manager.interactive_register()
        # Non-interactive mode - for scripts/CI
        elif email and password:
            success = auth_manager.register(email, password)
        # Hybrid mode - some params provided
        elif email and not password:
            from getpass import getpass
            password = getpass("Choose password: ")
            confirm_password = getpass("Confirm password: ")
            if password != confirm_password:
                console.print("❌ Passwords don't match", style="red")
                raise typer.Exit(1)
            success = auth_manager.register(email, password)
        else:
            console.print("❌ In non-interactive mode, provide credentials via:", style="red")
            console.print("   • --email and --password options")
            console.print("   • SECUREGENOMICS_EMAIL and SECUREGENOMICS_PASSWORD environment variables")
            console.print("   • Use interactive mode (default)")
            raise typer.Exit(1)
        
        if success:
            console.print("✅ Successfully registered and logged in", style="green")
        else:
            console.print("❌ Registration failed", style="red")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Registration error: {e}", style="red")
        raise typer.Exit(1)


@auth_app.command("logout")
def auth_logout() -> None:
    """Logout from SecureGenomics."""
    try:
        auth_manager = AuthManager()
        auth_manager.logout()
        console.print("✅ Successfully logged out", style="green")
    except Exception as e:
        console.print(f"❌ Logout error: {e}", style="red")
        raise typer.Exit(1)


@auth_app.command("whoami")
def auth_whoami() -> None:
    """Show current user information."""
    try:
        auth_manager = AuthManager()
        user_info = auth_manager.whoami()
        if user_info:
            console.print(f"Logged in as: {user_info['email']}", style="green")
        else:
            console.print("Not logged in", style="yellow")
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


@auth_app.command("quick")
def auth_quick() -> None:
    """Quick login using stored credentials or interactive prompt."""
    try:
        auth_manager = AuthManager()
        
        # Check if already authenticated
        if auth_manager.is_authenticated():
            user_info = auth_manager.whoami()
            email = user_info.get("email", "unknown") if user_info else "unknown"
            console.print(f"✅ Already logged in as {email}", style="green")
            return
        
        # Try interactive login
        success = auth_manager.interactive_login()
        if success:
            console.print("✅ Successfully logged in", style="green")
        else:
            console.print("❌ Login failed", style="red")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


@auth_app.command("delete_profile")
def auth_delete_profile() -> None:
    """Delete user profile and all data."""
    try:
        from rich.prompt import Confirm
        
        console.print("\n[bold red]⚠️  WARNING: This will permanently delete your profile and all data![/bold red]")
        console.print("This includes:")
        console.print("• Your account and authentication")
        console.print("• All projects and uploaded data")
        console.print("• All computation results")
        console.print("• This action cannot be undone\n")
        
        confirm = Confirm.ask("Are you absolutely sure you want to delete your profile?", default=False)
        if not confirm:
            console.print("Profile deletion cancelled")
            return
        
        # Double confirmation
        confirm2 = Confirm.ask("Type 'YES' to confirm deletion", default=False)
        if not confirm2:
            console.print("Profile deletion cancelled")
            return
        
        auth_manager = AuthManager()
        success = auth_manager.delete_profile()
        if success:
            console.print("✅ Profile deleted successfully", style="green")
        else:
            console.print("❌ Failed to delete profile", style="red")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


# ============================================================================
# PROTOCOL COMMANDS
# ============================================================================

@protocol_app.command("list")
def protocol_list(
    json_output: bool = typer.Option(False, "--json", help="Output protocols as JSON")
) -> None:
    """List available protocols from GitHub."""
    try:
        protocol_manager = ProtocolManager()
        protocols = protocol_manager.list_protocols()
        
        if json_output:
            import json
            # Convert protocols to dict format for JSON serialization
            protocols_data = []
            for protocol in protocols:
                protocols_data.append({
                    "name": protocol.name,
                    "description": protocol.description,
                    "github_url": protocol.github_url,
                    "commit_hash": protocol.commit_hash,
                    "version": protocol.version,
                    "analysis_type": protocol.analysis_type,
                    "local_supported": protocol.local_supported,
                    "aggregated_supported": protocol.aggregated_supported
                })
            
            result = {
                "success": True,
                "protocols": protocols_data,
                "count": len(protocols_data)
            }
            console.print(json.dumps(result))
        else:
            # Original table output
            if not protocols:
                console.print("No protocols found", style="yellow")
                return
            
            console.print("\n[bold blue]Available Protocols:[/bold blue]")
            for i, protocol in enumerate(protocols, 1):
                supports = []
                if protocol.local_supported:
                    supports.append("Local")
                if protocol.aggregated_supported:
                    supports.append("Aggregated")
                
                console.print(f"{i:2}. [bold green]{protocol.name}[/bold green]")
                console.print(f"    {protocol.description}")
                console.print(f"    Supports: {', '.join(supports)}")
                if protocol.analysis_type:
                    console.print(f"    Type: {protocol.analysis_type}")
                console.print()
                
    except Exception as e:
        if json_output:
            import json
            result = {
                "success": False,
                "error": str(e)
            }
            console.print(json.dumps(result))
        else:
            console.print(f"❌ Error listing protocols: {e}", style="red")
        raise typer.Exit(1)


@protocol_app.command("fetch")
def protocol_fetch(
    protocol_name: str = typer.Argument(..., help="Protocol name to fetch"),
) -> None:
    """Fetch (clone) protocol from GitHub."""
    try:
        protocol_manager = ProtocolManager()
        protocol = protocol_manager.fetch(protocol_name)
        console.print(f"✅ Successfully fetched protocol: {protocol.name}", style="green")
    except Exception as e:
        console.print(f"❌ Error fetching protocol: {e}", style="red")
        raise typer.Exit(1)


@protocol_app.command("verify")
def protocol_verify(
    protocol_name: str = typer.Argument(..., help="Protocol name to verify"),
) -> None:
    """Verify protocol integrity."""
    try:
        protocol_manager = ProtocolManager()
        is_valid = protocol_manager.verify(protocol_name)
        if is_valid:
            console.print(f"✅ Protocol {protocol_name} is valid", style="green")
        else:
            console.print(f"❌ Protocol {protocol_name} verification failed", style="red")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Error verifying protocol: {e}", style="red")
        raise typer.Exit(1)


@protocol_app.command("locals")
def protocol_locals() -> None:
    """List locally cached protocols with detailed information."""
    try:
        protocol_manager = ProtocolManager()
        local_protocols = protocol_manager.list_local_protocols()
        
        if not local_protocols:
            console.print("No protocols cached locally", style="yellow")
            console.print("💡 Use 'securegenomics protocol fetch <protocol-name>' to download protocols", style="blue")
            return
        
        console.print(f"\n[bold]Locally Cached Protocols ({len(local_protocols)} total):[/bold]")
        
        for protocol in local_protocols:
            # Protocol header with validation status
            status_indicator = "✅" if protocol["is_valid"] else "❌"
            console.print(f"\n{status_indicator} [bold cyan]{protocol['name']}[/bold cyan]")
            
            # Basic information
            console.print(f"   Description: {protocol['description']}")
            console.print(f"   Version: {protocol['version']}")
            console.print(f"   Analysis Type: {protocol['analysis_type']}")
            
            # Supported modes
            modes = protocol['modes']
            if modes:
                mode_indicators = []
                if protocol['local_supported']:
                    mode_indicators.append("[green]Local[/green]")
                if protocol['aggregated_supported']:
                    mode_indicators.append("[blue]Aggregated[/blue]")
                console.print(f"   Modes: {' • '.join(mode_indicators)}")
            else:
                console.print("   Modes: [dim]Unknown[/dim]")
            
            # Git information
            if protocol['commit_hash'] != "unknown":
                console.print(f"   Commit: {protocol['commit_hash']}")
                if protocol['commit_date'] != "unknown":
                    console.print(f"   Date: {protocol['commit_date']}")
            
            # Validation errors if any
            if not protocol["is_valid"] and protocol["validation_errors"]:
                console.print("   [red]Validation Errors:[/red]")
                for error in protocol["validation_errors"]:
                    console.print(f"     • {error}")
            
            # Cache location
            console.print(f"   [dim]Cache: {protocol['cache_path']}[/dim]")
        
        # Summary
        valid_count = sum(1 for p in local_protocols if p["is_valid"])
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"• Total cached: {len(local_protocols)}")
        console.print(f"• Valid protocols: {valid_count}")
        if valid_count < len(local_protocols):
            invalid_count = len(local_protocols) - valid_count
            console.print(f"• Invalid protocols: {invalid_count}")
            console.print("💡 Use 'securegenomics protocol refresh <protocol-name>' to fix invalid protocols", style="blue")
        
    except Exception as e:
        console.print(f"❌ Error listing local protocols: {e}", style="red")
        raise typer.Exit(1)


@protocol_app.command("remove_local")
def protocol_remove_local(
    protocol_name: str = typer.Argument(..., help="Protocol name to remove from local cache"),
) -> None:
    """Remove a locally cached protocol."""
    try:
        from rich.prompt import Confirm
        
        protocol_manager = ProtocolManager()
        
        # Show warning and confirmation
        console.print(f"\n[bold yellow]⚠️  WARNING: This will remove the local cache of protocol '{protocol_name}'[/bold yellow]")
        console.print("You will need to fetch it again to use it.")
        
        confirm = Confirm.ask(f"Are you sure you want to remove protocol '{protocol_name}' from local cache?", default=False)
        if not confirm:
            console.print("Protocol removal cancelled")
            return
        
        success = protocol_manager.remove_local_protocol(protocol_name)
        if success:
            console.print(f"💡 To re-download: 'securegenomics protocol fetch {protocol_name}'", style="blue")
    except Exception as e:
        console.print(f"❌ Error removing local protocol: {e}", style="red")
        raise typer.Exit(1)


@protocol_app.command("refresh")
def protocol_refresh(
    protocol_name: str = typer.Argument(..., help="Protocol name to refresh"),
) -> None:
    """Refresh a locally cached protocol (remove and re-download)."""
    try:
        protocol_manager = ProtocolManager()
        protocol_info = protocol_manager.refresh_protocol(protocol_name)
        
        console.print(f"✅ Protocol {protocol_name} refreshed successfully", style="green")
        console.print(f"   Version: {protocol_info.version or 'unknown'}")
        console.print(f"   Description: {protocol_info.description}")
        console.print(f"💡 Protocol is now ready for use", style="blue")
        
    except Exception as e:
        console.print(f"❌ Error refreshing protocol: {e}", style="red")
        raise typer.Exit(1)


# ============================================================================
# PROJECT COMMANDS  
# ============================================================================

@project_app.command("create")
def project_create(
    protocol_name: Optional[str] = typer.Option(None, "--protocol", "-p", help="Protocol name (non-interactive mode)"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Project description (optional)"),
    interactive: bool = typer.Option(True, "--interactive/--non-interactive", help="Use interactive mode (default: true)"),
    json_output: bool = typer.Option(False, "--json", help="Output result as JSON")
) -> None:
    """Create new aggregated analysis project.
    
    Interactive mode (default): Guides you through protocol selection
    Non-interactive mode: Requires --protocol option
    """
    try:
        project_manager = ProjectManager()
        
        if not interactive:
            # Non-interactive mode - requires protocol name
            if not protocol_name:
                console.print("❌ Non-interactive mode requires --protocol option", style="red")
                console.print("💡 Use 'securegenomics protocol list' to see available protocols", style="blue")
                raise typer.Exit(1)
            
            # Create project directly
            project_id = project_manager.create(protocol_name)
            
            if json_output:
                import json
                result = {
                    "success": True,
                    "project_id": project_id,
                    "protocol_name": protocol_name,
                    "description": description or None
                }
                console.print(json.dumps(result))
            else:
                console.print(f"✅ Created project: {project_id}", style="green")
                console.print(f"Protocol: {protocol_name}")
                if description:
                    console.print(f"Description: {description}")
        else:
            # Interactive mode - original behavior
            project_id = project_manager.interactive_create()
            
            if json_output:
                import json
                result = {
                    "success": True,
                    "project_id": project_id
                }
                console.print(json.dumps(result))
            else:
                console.print(f"✅ Created project: {project_id}", style="green")
                
    except Exception as e:
        if json_output:
            import json
            result = {
                "success": False,
                "error": str(e)
            }
            console.print(json.dumps(result))
        else:
            console.print(f"❌ Error creating project: {e}", style="red")
        raise typer.Exit(1)


@project_app.command("list")
def project_list(
    detailed: bool = typer.Option(False, "--detailed", help="Show detailed project information"),
) -> None:
    """List your projects."""
    try:
        project_manager = ProjectManager()
        response = project_manager.list_projects(detailed=detailed)
        
        if detailed:
            # Handle detailed response format - check if we got the expected format
            if isinstance(response, dict) and 'count' in response:
                # Got the expected detailed format
                if response['count'] == 0:
                    console.print("No projects found", style="yellow")
                    return
                
                projects = response['projects']
                console.print(f"\n[bold]Your Projects ({response['count']} total):[/bold]")
                
                for project in projects:
                    # Format creation date
                    from datetime import datetime
                    created_date = datetime.fromisoformat(project['created_at'].replace('Z', '+00:00'))
                    created_str = created_date.strftime("%Y-%m-%d %H:%M UTC")
                    
                    # Status color coding
                    status_colors = {
                        'pending': 'yellow',
                        'running': 'blue',
                        'completed': 'green',
                        'failed': 'red',
                        'no_jobs': 'dim'
                    }
                    status_color = status_colors.get(project['job_status'], 'white')
                    
                    # Project header
                    console.print(f"\n[bold cyan]🧬 {project['protocol_name']}[/bold cyan]")
                    console.print(f"   ID: [dim]{project['id']}[/dim]")
                    console.print(f"   Created: {created_str}")
                    console.print(f"   Status: [{status_color}]{project['job_status'].replace('_', ' ').title()}[/{status_color}]")
                    
                    # Crypto context status
                    context_status = "✅ Ready" if project['has_context'] else "❌ Not generated"
                    console.print(f"   Crypto Context: {context_status}")
                    
                    # Data information
                    if project['vcf_count'] > 0:
                        contributor_text = f"{project['contributor_count']} contributor(s)" if project['contributor_count'] > 1 else "1 contributor"
                        console.print(f"   Data: {project['vcf_count']} VCF file(s) from {contributor_text}")
                        
                        if project['contributors']:
                            console.print(f"   Contributors: {', '.join(project['contributors'])}")
                    else:
                        console.print("   Data: [dim]No VCF files uploaded yet[/dim]")
                    
                    # Job information
                    if project['latest_job_id']:
                        if project['latest_job_finished']:
                            finished_date = datetime.fromisoformat(project['latest_job_finished'].replace('Z', '+00:00'))
                            finished_str = finished_date.strftime("%Y-%m-%d %H:%M UTC")
                            console.print(f"   Latest Job: {project['latest_job_id']} (finished: {finished_str})")
                        elif project['latest_job_created']:
                            created_date = datetime.fromisoformat(project['latest_job_created'].replace('Z', '+00:00'))
                            created_str = created_date.strftime("%Y-%m-%d %H:%M UTC")
                            console.print(f"   Latest Job: {project['latest_job_id']} (started: {created_str})")
                    
                    # Protocol description
                    if project['protocol_description']:
                        console.print(f"   Description: [dim]{project['protocol_description'][:100]}{'...' if len(project['protocol_description']) > 100 else ''}[/dim]")
                
                # Summary
                console.print(f"\n[bold]Summary:[/bold]")
                console.print(f"• Total projects: {response['count']}")
                ready_projects = sum(1 for p in projects if p['has_context'])
                console.print(f"• Ready for use: {ready_projects}")
                active_projects = sum(1 for p in projects if p['job_status'] in ['pending', 'running'])
                if active_projects > 0:
                    console.print(f"• Active jobs: {active_projects}")
            else:
                # Server returned basic format even though we requested detailed
                # Fall back to basic display but inform the user
                console.print("[yellow]⚠️  Detailed information unavailable, showing basic listing[/yellow]")
                projects = response
                
                if not projects:
                    console.print("No projects found", style="yellow")
                    return
                
                console.print("\n[bold]Your Projects:[/bold]")
                for project in projects:
                    # Handle missing status field gracefully
                    status = project.get('status', 'unknown')
                    console.print(f"• {project['id']}: {project['protocol_name']} ({status})")
            
        else:
            # Handle basic response format
            projects = response
            
            if not projects:
                console.print("No projects found", style="yellow")
                return
            
            console.print("\n[bold]Your Projects:[/bold]")
            for project in projects:
                console.print(f"• {project['id']}: {project['protocol_name']} ({project['status']})")
    except Exception as e:
        console.print(f"❌ Error listing projects: {e}", style="red")
        raise typer.Exit(1)


@project_app.command("view")
def project_view(
    project_id: str = typer.Argument(..., help="Project ID to view"),
) -> None:
    """View detailed information for a specific project."""
    try:
        project_manager = ProjectManager()
        project_info = project_manager.view(project_id)
        
        console.print(f"\n[bold cyan]🧬 Project Details[/bold cyan]")
        console.print(f"   ID: [dim]{project_info['id']}[/dim]")
        console.print(f"   Protocol: [bold]{project_info['protocol_name']}[/bold]")
        
        # Format creation date
        from datetime import datetime
        created_date = datetime.fromisoformat(project_info['created_at'].replace('Z', '+00:00'))
        created_str = created_date.strftime("%Y-%m-%d %H:%M UTC")
        console.print(f"   Created: {created_str}")
        
        # Status color coding
        status_colors = {
            'pending': 'yellow',
            'running': 'blue',
            'completed': 'green',
            'failed': 'red',
            'no_jobs': 'dim'
        }
        status_color = status_colors.get(project_info['job_status'], 'white')
        console.print(f"   Status: [{status_color}]{project_info['job_status'].replace('_', ' ').title()}[/{status_color}]")
        
        # Crypto context status
        context_status = "✅ Ready" if project_info['has_context'] else "❌ Not generated"
        console.print(f"   Crypto Context: {context_status}")
        
        # Data information
        if project_info['vcf_count'] > 0:
            contributor_text = f"{project_info['contributor_count']} contributor(s)" if project_info['contributor_count'] > 1 else "1 contributor"
            console.print(f"   Data: {project_info['vcf_count']} VCF file(s) from {contributor_text}")
            
            if project_info['contributors']:
                console.print(f"   Contributors: {', '.join(project_info['contributors'])}")
        else:
            console.print("   Data: [dim]No VCF files uploaded yet[/dim]")
        
        # Job information
        if project_info['latest_job_id']:
            if project_info['latest_job_finished']:
                finished_date = datetime.fromisoformat(project_info['latest_job_finished'].replace('Z', '+00:00'))
                finished_str = finished_date.strftime("%Y-%m-%d %H:%M UTC")
                console.print(f"   Latest Job: {project_info['latest_job_id']} (finished: {finished_str})")
            elif project_info['latest_job_created']:
                created_date = datetime.fromisoformat(project_info['latest_job_created'].replace('Z', '+00:00'))
                created_str = created_date.strftime("%Y-%m-%d %H:%M UTC")
                console.print(f"   Latest Job: {project_info['latest_job_id']} (started: {created_str})")
        
        # Protocol description
        if project_info['protocol_description']:
            console.print(f"\n[bold]Description:[/bold]")
            console.print(f"   {project_info['protocol_description']}")
        
        # Next steps guidance
        console.print(f"\n[bold]Next Steps:[/bold]")
        if not project_info['has_context']:
            console.print(f"   💡 Generate crypto context: [blue]securegenomics crypto_context generate {project_id}[/blue]")
        elif project_info['vcf_count'] == 0:
            console.print(f"   💡 Upload VCF data: [blue]securegenomics data encode_encrypt_upload {project_id} <vcf-file>[/blue]")
        elif project_info['job_status'] == 'no_jobs':
            console.print(f"   💡 Start computation: [blue]securegenomics project run {project_id}[/blue]")
        elif project_info['job_status'] == 'completed':
            console.print(f"   💡 View results: [blue]securegenomics project result {project_id}[/blue]")
        elif project_info['job_status'] in ['pending', 'running']:
            console.print(f"   💡 Check status: [blue]securegenomics project job_status {project_id}[/blue]")
        
    except Exception as e:
        console.print(f"❌ Error viewing project: {e}", style="red")
        raise typer.Exit(1)


@project_app.command("list_saved_results")
def project_list_saved_results(
    project_id: str = typer.Argument(..., help="Project ID"),
) -> None:
    """List all saved encrypted and decrypted results for a project."""
    try:
        project_manager = ProjectManager()
        saved_results = project_manager.list_saved_results(project_id)
        
        if not saved_results:
            console.print(f"No saved results found for project {project_id}")
            return
        
        console.print(f"\n[bold]Saved Results for Project {project_id}:[/bold]")
        
        from rich.table import Table
        import datetime
        
        table = Table(title=f"Saved Results ({len(saved_results)} files)")
        table.add_column("Type", style="magenta")
        table.add_column("Filename", style="cyan")
        table.add_column("Size", style="green")
        table.add_column("Created", style="yellow")
        table.add_column("Path", style="dim")
        
        for result in saved_results:
            # Format file size
            size_bytes = result["size_bytes"]
            if size_bytes > 1024 * 1024:
                size_str = f"{size_bytes / (1024 * 1024):.1f} MB"
            elif size_bytes > 1024:
                size_str = f"{size_bytes / 1024:.1f} KB"
            else:
                size_str = f"{size_bytes} B"
            
            # Format creation time
            created_time = datetime.datetime.fromtimestamp(result["created_at"])
            created_str = created_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Format type with emoji
            type_display = "🔒 Encrypted" if result["type"] == "encrypted" else "🔓 Decrypted"
            
            table.add_row(
                type_display,
                result["filename"],
                size_str,
                created_str,
                result["full_path"]
            )
        
        console.print(table)
        console.print(f"\n[dim]Results directory: {project_manager._get_results_dir(project_id)}[/dim]")
        
    except Exception as e:
        console.print(f"❌ Error listing saved results: {e}", style="red")
        raise typer.Exit(1)


@project_app.command("delete")
def project_delete(
    project_id: str = typer.Argument(..., help="Project ID to delete"),
) -> None:
    """Delete a project and all associated data."""
    try:
        from rich.prompt import Confirm
        
        console.print(f"\n[bold red]⚠️  WARNING: This will permanently delete project {project_id}![/bold red]")
        console.print("This includes:")
        console.print("• All uploaded VCF files")
        console.print("• All computation results")
        console.print("• All project metadata")
        console.print("• Local crypto context")
        console.print("• This action cannot be undone\n")
        
        confirm = Confirm.ask(f"Are you sure you want to delete project {project_id}?", default=False)
        if not confirm:
            console.print("Project deletion cancelled")
            return
        
        project_manager = ProjectManager()
        success = project_manager.delete(project_id)
        if success:
            console.print(f"✅ Project {project_id} deleted successfully", style="green")
        else:
            console.print(f"❌ Failed to delete project {project_id}", style="red")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Error deleting project: {e}", style="red")
        raise typer.Exit(1)



# ============================================================================
# DATA COMMANDS
# ============================================================================

@data_app.command("encode")
def data_encode(
    project_id: str = typer.Argument(..., help="Project ID"),
    vcf_file: Path = typer.Argument(..., help="VCF file to encode", exists=True),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Output directory (default: project data cache)"),
) -> None:
    """Encode VCF file using project's protocol (step 1 of 3)."""
    try:
        data_manager = DataManager()
        encoded_path = data_manager.encode_vcf(project_id, vcf_file, output_dir)
        console.print(f"✅ Encoded {vcf_file.name} for project {project_id}")
        console.print(f"📁 Output: {encoded_path}")
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


@data_app.command("encrypt")
def data_encrypt(
    project_id: str = typer.Argument(..., help="Project ID"),
    encoded_file: Path = typer.Argument(..., help="Encoded file to encrypt", exists=True),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Output directory (default: project data cache)"),
) -> None:
    """Encrypt encoded data using project's crypto context (step 2 of 3)."""
    try:
        data_manager = DataManager()
        encrypted_path, stats = data_manager.encrypt_vcf(project_id, encoded_file, output_dir)
        console.print(f"✅ Encrypted {encoded_file.name} for project {project_id}")
        console.print(f"📁 Output: {encrypted_path}")
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


@data_app.command("upload")
def data_upload(
    project_id: str = typer.Argument(..., help="Project ID"),
    encrypted_file: Path = typer.Argument(..., help="Encrypted file to upload", exists=True),
) -> None:
    """Upload encrypted data file to server (step 3 of 3)."""
    try:
        data_manager = DataManager()
        data_manager.upload_data(project_id, encrypted_file)
        console.print(f"✅ Uploaded {encrypted_file.name} to project {project_id}")
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


@data_app.command("encode_encrypt_upload")
def data_encode_encrypt_upload(
    project_id: str = typer.Argument(..., help="Project ID"),
    vcf_file: Path = typer.Argument(..., help="VCF file to process", exists=True),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Output directory for intermediate files (default: project data cache)"),
) -> None:
    """Complete VCF processing pipeline: encode, encrypt, and upload (combined operation)."""
    try:
        data_manager = DataManager()
        data_manager.encode_encrypt_upload(project_id, vcf_file, output_dir)
        console.print(f"✅ Completed full pipeline for {vcf_file.name} in project {project_id}")
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


# ============================================================================
# LOCAL COMMANDS
# ============================================================================

@local_app.command("analyze")
def local_analyze(
    protocol_name: str = typer.Argument(..., help="Protocol name"),
    vcf_file: Path = typer.Argument(..., help="VCF file to analyze", exists=True),
) -> None:
    """Run local analysis on VCF file."""
    try:
        analyzer = LocalAnalyzer()
        results = analyzer.analyze(protocol_name, vcf_file)
        console.print(f"✅ Analysis completed for {vcf_file.name}", style="green")
        console.print("\nResults:")
        console.print(results)
    except Exception as e:
        console.print(f"❌ Error running analysis: {e}", style="red")
        raise typer.Exit(1)


# ============================================================================
# SYSTEM COMMANDS
# ============================================================================

@system_app.command("status")
def system_status() -> None:
    """Check system status and connectivity."""
    try:
        config_manager = ConfigManager()
        status = config_manager.get_system_status()
        
        console.print("\n[bold]System Status:[/bold]")
        console.print(f"CLI Version: {__version__}")
        console.print(f"Config Directory: {status['config_dir']}")
        console.print(f"Server Connection: {'✅' if status['server_connected'] else '❌'}")
        console.print(f"Cached Protocols: {status['cached_protocols']}")
        
    except Exception as e:
        console.print(f"❌ Error checking status: {e}", style="red")
        raise typer.Exit(1)


@system_app.command("help")
def system_help() -> None:
    """Show detailed help information."""
    console.print("""
[bold]SecureGenomics CLI Help[/bold]

[bold]Two Analysis Modes:[/bold]
• Local-only: Run analysis locally without encryption or server
• Aggregated: Secure multi-party computation across encrypted datasets

[bold]Common Workflows:[/bold]

[bold]1. Local Analysis (No server needed):[/bold]
   securegenomics protocol list
   securegenomics local analyze alzheimers-risk sample.vcf

[bold]2. Aggregated Analysis (Multi-party):[/bold]
   securegenomics auth login
   securegenomics project create                          # Interactive - choose protocol
   securegenomics project generate_upload_context <project-id>
   securegenomics data encode_encrypt_upload <project-id> data.vcf
   securegenomics project run <project-id>
   securegenomics project stop <project-id>              # Stop running job if needed
   securegenomics project job_status <project-id>        # Check job status
   securegenomics project result <project-id>
   securegenomics project clear_protocol_cache <project-id>    # Clear protocol cache
   securegenomics project refresh_protocol_cache <project-id>  # Refresh protocol cache

[bold]Configuration:[/bold]
   ~/.securegenomics/config.json   - CLI settings
   ~/.securegenomics/auth.json     - Authentication tokens
   ~/.securegenomics/protocols/    - Cached protocols
   
[bold]For more help on specific commands:[/bold]
   securegenomics <command> --help
""")


# ============================================================================
# CRYPTO CONTEXT COMMANDS
# ============================================================================

@crypto_context_app.command("generate")
def crypto_context_generate(
    project_id: str = typer.Argument(..., help="Project ID"),
) -> None:
    """Generate FHE crypto context locally for project (does not upload)."""
    try:
        crypto_context_manager = CryptoContextManager()
        
        # Validate that crypto context generation is allowed
        console.print(f"🔍 Validating project {project_id}...")
        
        # Check if server already has public context
        if crypto_context_manager.has_server_crypto_context(project_id):
            console.print(f"❌ Project {project_id} already has a public crypto context on the server.", style="red")
            console.print("Each project can only have one crypto context for security reasons.", style="red")
            raise typer.Exit(1)
        
        # Check if local context already exists
        if crypto_context_manager.has_local_crypto_context(project_id):
            console.print(f"❌ Local crypto context already exists for project {project_id}.", style="red")
            console.print("Each project can only have one crypto context for security reasons.", style="red")
            console.print(f"💡 Use 'securegenomics crypto_context upload {project_id}' to upload existing context", style="blue")
            console.print("   or delete the local context first if you want to regenerate.", style="blue")
            raise typer.Exit(1)
        
        console.print("✅ Validation passed - generating crypto context locally", style="green")
        
        # Generate crypto context (local only, no upload)
        crypto_context_manager.generate_crypto_context(project_id)
        console.print(f"✅ Generated crypto context locally for project {project_id}", style="green")
        console.print(f"💡 Next step: Upload to server with 'securegenomics crypto_context upload {project_id}'", style="blue")
        
    except typer.Exit:
        # Re-raise typer.Exit to preserve exit codes
        raise
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


@crypto_context_app.command("upload")
def crypto_context_upload(
    project_id: str = typer.Argument(..., help="Project ID"),
) -> None:
    """Upload existing local crypto context to server."""
    try:
        crypto_context_manager = CryptoContextManager()
        
        console.print(f"🔍 Validating project {project_id}...")
        
        # Check if server already has public context
        if crypto_context_manager.has_server_crypto_context(project_id):
            console.print(f"❌ Project {project_id} already has a public crypto context on the server.", style="red")
            console.print("Each project can only have one crypto context for security reasons.", style="red")
            raise typer.Exit(1)
        
        # Check if local context exists
        if not crypto_context_manager.has_local_crypto_context(project_id):
            console.print(f"❌ No local crypto context found for project {project_id}.", style="red")
            console.print(f"💡 Use 'securegenomics crypto_context generate {project_id}' to generate a new context", style="blue")
            raise typer.Exit(1)
        
        console.print("✅ Validation passed - uploading existing crypto context", style="green")
        
        # Upload public context to server
        try:
            crypto_context_manager.upload_crypto_context(project_id)
            console.print(f"✅ Uploaded public crypto context for project {project_id}", style="green")
        except Exception as upload_error:
            # Check if it's a duplicate context error
            if "already exists on server" in str(upload_error) or "already has a public crypto context" in str(upload_error):
                console.print(f"❌ {upload_error}", style="red")
                console.print("💡 This validation should have been caught earlier. Please try refreshing and check again.", style="blue")
                raise typer.Exit(1)
            else:
                # Re-raise other upload errors
                raise
        
    except typer.Exit:
        # Re-raise typer.Exit to preserve exit codes
        raise
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


@crypto_context_app.command("download")
def crypto_context_download(
    project_id: str = typer.Argument(..., help="Project ID"),
) -> None:
    """Download public crypto context from server."""
    try:
        from securegenomics.crypto import FHEManager
        
        console.print(f"🔍 Downloading public crypto context for project {project_id}...")
        
        # Download context using FHEManager
        fhe_manager = FHEManager()
        fhe_manager.download_public_context(project_id)
        
        # Log audit event
        from securegenomics.auth import AuthManager
        auth_manager = AuthManager()
        # auth_manager._log_audit_event("crypto_context_download", project_id=project_id)
        
        console.print(f"💾 Context saved locally and ready for data encryption")
        console.print(f"💡 You can now encrypt VCF data with: 'securegenomics data encrypt {project_id} <encoded-file>'", style="blue")
        
    except typer.Exit:
        # Re-raise typer.Exit to preserve exit codes
        raise
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


@crypto_context_app.command("generate_upload")
def crypto_context_generate_upload(
    project_id: str = typer.Argument(..., help="Project ID"),
) -> None:
    """Generate FHE crypto context for project and upload to server (combined operation)."""
    try:
        crypto_context_manager = CryptoContextManager()
        crypto_context_manager.generate_upload_crypto_context(project_id)
        
    except typer.Exit:
        # Re-raise typer.Exit to preserve exit codes
        raise
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        raise typer.Exit(1)


@crypto_context_app.command("delete")
def crypto_context_delete(
    project_id: str = typer.Argument(..., help="Project ID"),
    local: bool = typer.Option(False, "--local", help="Delete local crypto context"),
    server: bool = typer.Option(False, "--server", help="Delete server crypto context"),
) -> None:
    """Delete crypto context from local storage or server."""
    try:
        # Validate that exactly one option is provided
        if not local and not server:
            console.print("❌ You must specify either --local or --server", style="red")
            console.print("Usage examples:", style="blue")
            console.print(f"  securegenomics crypto_context delete --local {project_id}")
            console.print(f"  securegenomics crypto_context delete --server {project_id}")
            raise typer.Exit(1)
        
        if local and server:
            console.print("❌ Cannot specify both --local and --server. Choose one.", style="red")
            raise typer.Exit(1)
        
        crypto_context_manager = CryptoContextManager()
        
        if local:
            # Delete local crypto context
            console.print(f"🗑️  Deleting local crypto context for project {project_id}...")
            
            # Check if local context exists
            if not crypto_context_manager.has_local_crypto_context(project_id):
                console.print(f"❌ No local crypto context found for project {project_id}", style="red")
                raise typer.Exit(1)
            
            # Confirmation prompt
            from rich.prompt import Confirm
            console.print("\n[bold red]⚠️  WARNING: This will delete your local crypto context![/bold red]")
            console.print("• You will lose the ability to decrypt results for this project")
            console.print("• You cannot regenerate the same context - each context is unique")
            console.print("• The server crypto context will remain unaffected")
            console.print("• This action cannot be undone\n")
            
            confirm = Confirm.ask(f"Are you sure you want to delete the local crypto context for project {project_id}?", default=False)
            if not confirm:
                console.print("Local crypto context deletion cancelled")
                return
            
            # Delete local context
            success = crypto_context_manager.delete_local_crypto_context(project_id)
            if success:
                console.print(f"✅ Local crypto context deleted for project {project_id}", style="green")
                console.print("⚠️  You can no longer decrypt results for this project locally", style="yellow")
            else:
                console.print(f"❌ Failed to delete local crypto context for project {project_id}", style="red")
                raise typer.Exit(1)
        
        elif server:
            # Delete server crypto context  
            console.print(f"🗑️  Deleting server crypto context for project {project_id}...")
            
            # Check if server context exists
            if not crypto_context_manager.has_server_crypto_context(project_id):
                console.print(f"❌ No server crypto context found for project {project_id}", style="red")
                raise typer.Exit(1)
            
            # Confirmation prompt
            from rich.prompt import Confirm
            console.print("\n[bold red]⚠️  WARNING: This will delete the server crypto context![/bold red]")
            console.print("• Other participants will lose the ability to encrypt data for this project")
            console.print("• The project will no longer accept new encrypted data")
            console.print("• Your local crypto context will remain unaffected")
            console.print("• You cannot upload the same context again - each context is unique")
            console.print("• This action cannot be undone\n")
            
            confirm = Confirm.ask(f"Are you sure you want to delete the server crypto context for project {project_id}?", default=False)
            if not confirm:
                console.print("Server crypto context deletion cancelled")
                return
            
            # Delete server context
            success = crypto_context_manager.delete_server_crypto_context(project_id)
            if success:
                console.print(f"✅ Server crypto context deleted for project {project_id}", style="green")
                console.print("⚠️  The project can no longer accept new encrypted data", style="yellow")
            else:
                console.print(f"❌ Failed to delete server crypto context for project {project_id}", style="red")
                raise typer.Exit(1)
        
    except typer.Exit:
        # Re-raise typer.Exit to preserve exit codes
        raise
    except Exception as e:
        error_msg = _sanitize_error_message(str(e))
        console.print(f"❌ Error: {error_msg}", style="red")
        raise typer.Exit(1)


@project_app.command("run")
def project_run(
    project_id: str = typer.Argument(..., help="Project ID"),
) -> None:
    """Start computation for project."""
    try:
        project_manager = ProjectManager()
        job_id = project_manager.run(project_id)
        console.print(f"✅ Started computation for project {project_id}", style="green")
        console.print(f"Job ID: {job_id}")
    except Exception as e:
        console.print(f"❌ Error starting computation: {e}", style="red")
        raise typer.Exit(1)


@project_app.command("stop")
def project_stop(
    project_id: str = typer.Argument(..., help="Project ID"),
) -> None:
    """Stop running computation for project."""
    try:
        project_manager = ProjectManager()
        job_id = project_manager.stop(project_id)
        console.print(f"✅ Stopped computation for project {project_id}", style="green")
        console.print(f"Job ID: {job_id}")
    except Exception as e:
        console.print(f"❌ Error stopping computation: {e}", style="red")
        raise typer.Exit(1)


@project_app.command("job_status")
def project_job_status(
    project_id: str = typer.Argument(..., help="Project ID"),
) -> None:
    """Check job status for project."""
    try:
        project_manager = ProjectManager()
        status = project_manager.get_job_status(project_id)
        console.print(f"Project {project_id} status: {status['status']}")
        if status.get('events'):
            console.print("\nJob Events:")
            for event in status['events']:
                console.print(f"• {event['timestamp']}: {event['step']} - {event['message']}")
    except Exception as e:
        console.print(f"❌ Error checking status: {e}", style="red")
        raise typer.Exit(1)


@project_app.command("result")
def project_result(
    project_id: str = typer.Argument(..., help="Project ID"),
) -> None:
    """Get results for completed project."""
    try:
        project_manager = ProjectManager()
        results = project_manager.get_result(project_id)
        console.print(f"✅ Results for project {project_id}:", style="green")
        console.print(results)
    except Exception as e:
        console.print(f"❌ Error getting results: {e}", style="red")
        raise typer.Exit(1)


@project_app.command("delete")
def project_delete(
    project_id: str = typer.Argument(..., help="Project ID to delete"),
) -> None:
    """Delete a project and all associated data."""
    try:
        from rich.prompt import Confirm
        
        console.print(f"\n[bold red]⚠️  WARNING: This will permanently delete project {project_id}![/bold red]")
        console.print("This includes:")
        console.print("• All uploaded VCF files")
        console.print("• All computation results")
        console.print("• All project metadata")
        console.print("• Local crypto context")
        console.print("• This action cannot be undone\n")
        
        confirm = Confirm.ask(f"Are you sure you want to delete project {project_id}?", default=False)
        if not confirm:
            console.print("Project deletion cancelled")
            return
        
        project_manager = ProjectManager()
        success = project_manager.delete(project_id)
        if success:
            console.print(f"✅ Project {project_id} deleted successfully", style="green")
        else:
            console.print(f"❌ Failed to delete project {project_id}", style="red")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Error deleting project: {e}", style="red")
        raise typer.Exit(1)


# Entry point
def _sanitize_error_message(error_msg: str) -> str:
    """Sanitize error message to prevent Rich markup errors with binary data."""
    # Convert to string if it's bytes
    if isinstance(error_msg, bytes):
        try:
            error_msg = error_msg.decode('utf-8', errors='replace')
        except:
            error_msg = repr(error_msg)
    
    # Replace non-printable characters that could confuse Rich markup
    import re
    # Replace any character that's not printable ASCII, keeping basic punctuation
    sanitized = re.sub(r'[^\x20-\x7E\n\r\t]', '?', str(error_msg))
    
    # Escape Rich markup characters to prevent parsing issues
    sanitized = sanitized.replace('[', '\\[').replace(']', '\\]')
    
    return sanitized


def main() -> None:
    """Main entry point for the CLI."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n⚠️  Operation cancelled by user", style="yellow")
        sys.exit(130)
    except Exception as e:
        # Sanitize error message to prevent Rich markup errors
        error_msg = _sanitize_error_message(str(e))
        console.print(f"\n❌ Unexpected error: {error_msg}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    main() 