#!/usr/bin/env python3
"""Command-line interface for the Cold Wallet."""
import click
from rich.console import Console
from rich.table import Table
from pathlib import Path
from getpass import getpass
import sys
import json

from app.crypto.keystore import KeyStore

console = Console()


def show_error(message: str):
    """Display error message."""
    console.print(f"[bold red]❌ Error:[/bold red] {message}")


def show_success(message: str):
    """Display success message."""
    console.print(f"[bold green]✅ Success:[/bold green] {message}")


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """🔐 Cold Crypto Wallet - Secure Key Management"""
    pass


@cli.command()
@click.option('--scheme', default='Ed25519', help='Signature scheme')
def init(scheme):
    """Initialize a new wallet keystore."""
    console.print(f"\n🔑 Creating new {scheme} wallet...\n")
    
    try:
        console.print("[cyan]Enter passphrase (min 12 characters):[/cyan]")
        passphrase = getpass("Passphrase: ")
        
        if len(passphrase) < 12:
            show_error("Passphrase must be at least 12 characters")
            sys.exit(1)
        
        passphrase_confirm = getpass("Confirm: ")
        if passphrase != passphrase_confirm:
            show_error("Passphrases don't match")
            sys.exit(1)
        
        console.print("\n[cyan]⏳ Generating keys...[/cyan]")
        address, pubkey = KeyStore.create(passphrase, scheme)
        
        console.print()
        show_success("Wallet created!")
        console.print(f"\n[bold cyan]Address:[/bold cyan]  [green]{address}[/green]")
        console.print(f"[bold cyan]Pubkey:[/bold cyan]   {pubkey[:40]}...")
        console.print(f"[bold cyan]File:[/bold cyan]keystores/wallet_{address[:10]}.json")
        console.print("\n[yellow]⚠️  Keep your passphrase safe![/yellow]\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")
        sys.exit(0)
    except Exception as e:
        show_error(str(e))
        sys.exit(1)


@cli.command()
@click.option('--keystore', required=True, type=click.Path(exists=True))
def address(keystore):
    """Display wallet address."""
    try:
        with open(keystore, 'r') as f:
            data = json.load(f)
        
        table = Table(title="💼 Wallet Info")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Address", data['address'])
        table.add_row("Pubkey", data['pubkey_b64'][:50] + "...")
        table.add_row("Created", data['created'])
        
        console.print()
        console.print(table)
        console.print()
        
    except Exception as e:
        show_error(str(e))
        sys.exit(1)


@cli.command(name='list')  # ← Agregar esto
def list_keystores():      # ← Cambiar nombre
    """List all keystores."""
    keystores_dir = Path("keystores")
    keystores = list(keystores_dir.glob("wallet_*.json"))
    
    if not keystores:
        console.print("\n[yellow]No keystores found.[/yellow]")
        console.print("Create one: [cyan]python3 -m app.main init[/cyan]\n")
        return
    
    table = Table(title=f"📁 {len(keystores)} Keystore(s)")
    table.add_column("#", style="cyan")
    table.add_column("Address", style="green")
    table.add_column("Created")
    
    for i, ks in enumerate(keystores, 1):
        try:
            with open(ks) as f:
                data = json.load(f)
            table.add_row(str(i), data['address'][:20] + "...", data['created'][:10])
        except:
            table.add_row(str(i), "[red]Error[/red]", "")
    
    console.print()
    console.print(table)
    console.print()

@cli.command()
def status():
    """Show wallet status."""
    keystores = len(list(Path("keystores").glob("wallet_*.json")))
    inbox = len(list(Path("inbox").glob("*.json")))
    outbox = len(list(Path("outbox").glob("*.json")))
    verified = len(list(Path("verified").glob("*.json")))
    
    console.print(f"\n💼 [bold cyan]Cold Wallet Status[/bold cyan]")
    console.print(f"🔐 Keystores: {keystores}")
    console.print(f"📥 Inbox: {inbox}")
    console.print(f"📤 Outbox: {outbox}")
    console.print(f"✅ Verified: {verified}\n")

@cli.command()
@click.option('--keystore', required=True, type=click.Path(exists=True), help='Path to keystore')
@click.option('--to', required=True, help='Recipient address')
@click.option('--value', required=True, help='Amount to send')
@click.option('--nonce', required=True, type=int, help='Transaction nonce')
@click.option('--data-hex', default='', help='Optional data payload')
def sign(keystore, to, value, nonce, data_hex):
    """Sign a transaction and save to outbox."""
    from app.crypto.keystore import KeyStore
    from app.transaction.models import Transaction
    from app.transaction.signer import Signer
    from datetime import datetime
    import json
    
    try:
        # Load keystore to get from address
        with open(keystore) as f:
            ks_data = json.load(f)
        from_address = ks_data['address']
        
        # Show transaction preview
        console.print("\n📝 [bold cyan]Transaction Preview[/bold cyan]")
        console.print(f"From:  {from_address}")
        console.print(f"To:    {to}")
        console.print(f"Value: {value}")
        console.print(f"Nonce: {nonce}")
        if data_hex:
            console.print(f"Data:  {data_hex[:40]}...")
        console.print()
        
        # Confirm
        if not click.confirm("Sign this transaction?", default=True):
            console.print("[yellow]Cancelled.[/yellow]")
            return
        
        # Get passphrase
        passphrase = getpass("Keystore passphrase: ")
        
        # Load private key
        console.print("\n[cyan]⏳ Loading keystore...[/cyan]")
        signing_key = KeyStore.load(Path(keystore), passphrase)
        
        # Create transaction
        tx = Transaction(
            from_address=from_address,
            to=to,
            value=value,
            nonce=nonce,
            data_hex=data_hex
        )
        
        # Sign
        console.print("[cyan]⏳ Signing transaction...[/cyan]")
        signed_tx = Signer.sign(signing_key, tx)
        
        # Save to outbox
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"tx_{timestamp}_{nonce}.json"
        filepath = Path("outbox") / filename
        
        with open(filepath, 'w') as f:
            json.dump(signed_tx.to_dict(), f, indent=2)
        
        console.print()
        show_success("Transaction signed!")
        console.print(f"📤 Saved to: [cyan]{filepath}[/cyan]\n")
        
    except ValueError as e:
        show_error(f"Incorrect passphrase or corrupted keystore")
        sys.exit(1)
    except Exception as e:
        show_error(str(e))
        sys.exit(1)
@cli.command()
@click.option('--path', required=True, type=click.Path(exists=True), help='Path to transaction file')
def recv(path):
    """Verify a received transaction."""
    from app.transaction.models import SignedTransaction
    from app.transaction.verifier import Verifier
    import json
    import shutil
    
    console.print("\n✅ [bold cyan]Verifying Transaction[/bold cyan]\n")
    
    try:
        # Load transaction
        with open(path) as f:
            data = json.load(f)
        
        signed_tx = SignedTransaction.from_dict(data)
        
        # Verify
        console.print("[cyan]⏳ Verifying signature...[/cyan]")
        result = Verifier.verify(signed_tx)
        
        console.print()
        
        if result['valid']:
            console.print("[bold green]✅ VALID TRANSACTION[/bold green]\n")
            
            # Show details
            tx = signed_tx.tx
            console.print(f"From:  {tx.from_address}")
            console.print(f"To:    {tx.to}")
            console.print(f"Value: {tx.value}")
            console.print(f"Nonce: {tx.nonce}")
            console.print(f"Time:  {tx.timestamp}")
            console.print()
            
            # Move to verified
            verified_path = Path("verified") / Path(path).name
            shutil.move(path, verified_path)
            console.print(f"📁 Moved to: [cyan]{verified_path}[/cyan]\n")
            
        else:
            console.print(f"[bold red]❌ INVALID TRANSACTION[/bold red]")
            console.print(f"Reason: {result['reason']}\n")
        
    except Exception as e:
        show_error(str(e))
        sys.exit(1)
